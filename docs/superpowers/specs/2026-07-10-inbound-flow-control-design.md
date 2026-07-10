# 设计:入站流控背压(credit-on-consume)

- 日期:2026-07-10
- 对应 review 项:#5(入站流控无背压)
- 目标库:`zig-http2`(gRPC / 自研 CDN 的 HTTP/2 底座)

## 背景与动机

当前 `server.zig` 的入站(接收侧)流控没有背压:

- `handleData` 收到**每个** DATA 帧后,**立即**在 connection 级和 stream 级各发一个 `WINDOW_UPDATE`,补满整帧长度 —— 在 handler 通过 `body_reader`(`streamRead`)消费之前。窗口永远被顶回,对端永不因流控停等。
- 服务端**根本不跟踪**接收窗口余量:它只是对每帧盲目补窗。唯一的界限是 `rx_buf` 的 8 MB 硬上限(`max_request_body`),越过就 `RST_STREAM(FLOW_CONTROL_ERROR)`。

后果:慢 handler 遇到快上传方时,数据一路堆进 `rx_buf` 到 8 MB,然后流被 RST —— 对一个合法的慢消费者(gRPC client-streaming、CDN 大上传)是意外且粗暴的失败。

## 目标

实现完整的 HTTP/2 接收侧流控(RFC 7540 §6.9):**收到即扣减、消费才补窗**,双层(per-stream + connection)。慢 handler 自然对快上传方施加背压(对端 send window 归零而阻塞),而不是被 RST。用窗口本身作为未消费缓冲的界限,移除独立的 8 MB 常量。

## 已核实事实 / 现状锚点

- `handleData`(`server.zig`)当前流程:先剥离 PADDED(`pad > data.len` → `GOAWAY(protocol_error)`),再立即双层补窗,再在 `streams_mu → rx_mu` 下缓存进 `rx_buf`,`max_request_body` 越限则 `RST(flow_control_error)`。
- `streamRead`(H2Stream)在 `rx_mu` 下从 `rx_buf`/`rx_off` 取字节返回给 handler。
- 发送侧流控(`send_window` / `conn.send_window` / `send_mu` / `applyInitialWindow`)是**对端→我方**方向,**本设计不涉及**,保持不变。
- RFC 7540 §6.9.1:connection 接收窗初值固定 65535,**不受** `SETTINGS_INITIAL_WINDOW_SIZE` 影响(后者只作用于 stream);放大 connection 窗需在 stream 0 发 `WINDOW_UPDATE`。
- 流控长度按**整帧 payload**(含 pad 长度字节 + padding)计,padding 也算流控。

## 模型:两层接收窗口

### per-stream(H2Stream 新增字段,`rx_mu` 保护)
- `recv_window: i64` —— 对端在该流上还能发的字节数。初值 = `cfg.initial_window_size`(即我们通告的 `SETTINGS_INITIAL_WINDOW_SIZE`)。
- `recv_pending: i64` —— 已"消费"但尚未 `WINDOW_UPDATE` 的累计补窗量。

### connection(Connection 新增字段,新 `recv_mu` 保护)
- `recv_mu: Io.Mutex`
- `conn_recv_window: i64` —— 整连接聚合还能收的字节数。初值 = `cfg.connection_window_size`(启动时若 >65535 通过 stream-0 `WINDOW_UPDATE(delta)` 放大)。
- `conn_recv_pending: i64` —— 连接级累计补窗量。

## 收到 DATA(reader 线程,`handleData`)—— 只扣减 + 强制

保持现有 PADDED 校验在最前。令 `fc_len = payload.len`(整帧,流控长度),`data` = 去 padding 后的 body,`overhead = fc_len - data.len`(pad 字节 + padding;非 padded 时为 0)。

1. **连接级扣减 + 强制**:持 `recv_mu`,`conn_recv_window -= fc_len`;若 `< 0` → 释放锁,`GOAWAY(FLOW_CONTROL_ERROR)`,返回 false(致命)。否则释放锁。
2. **查 stream**(`streams_mu`):
   - **不存在**:整帧不会被任何 handler 消费 → 把 `fc_len` 立刻补回**连接**窗(经 conn 补窗路径),返回 true。
   - **存在**(持 `rx_mu`):
     3. `recv_window -= fc_len`;若 `< 0` → `RST_STREAM(FLOW_CONTROL_ERROR)`;**且把 `fc_len` 补回连接窗**(整帧不入缓冲、不会被消费),返回 true。
     4. 缓存 `data` 进 `rx_buf`;若 append OOM → `RST(internal_error)`,**且把 `fc_len` 补回连接窗**(同上)。`end_stream` 置 `rx_eof`。
     5. **padding 开销即刻补窗**:若 `overhead > 0`,把 `overhead` 计入 stream 与 conn 的 pending(见"补窗")—— padding 是帧结构,收到即"消费"。(此帧的 `data` 部分留待消费或流终止时返还,见下。)
- **移除** `max_request_body` 常量与那段 8 MB 检查:合规对端 unconsumed 天然 ≤ `cfg.initial_window_size`;越窗在步骤 3 就被 `RST` 拦下。

### 连接窗返还的总不变式(避免泄漏)
每一份从 `conn_recv_window` 扣掉的 `fc_len`,必须恰好返还一次,在这些字节"了结"时:
- `overhead`(padding/帧结构):收到即返还(步骤 5)。
- `data` 被缓存后:
  - 被 handler 消费 → 消费时返还(`streamRead`,批量);
  - **流终止时仍未消费**(handler 提前返回不读 body、被 RST、deadline 等)→ **在流终止路径把 rx_buf 里的未消费 `data`(`rx_buf.items.len - rx_off`)返还连接窗**。这一步必不可少:否则不读 body 的 handler 会永久吃掉连接窗额度,拖垮其它流。
- `data` 因步骤 3/4 被丢弃(未入缓冲)→ 丢弃时按 `fc_len` 立刻返还(见上)。

等价表述:**`data` 字节离开 rx_buf 时返还连接窗 —— 无论经由消费(`streamRead`)还是流终止时的丢弃**;从不入 rx_buf 的整帧(stream 不存在 / 越窗 RST / OOM)按 `fc_len` 就地返还。stream 级窗口无此问题(流终止即整体丢弃,无共享)。

## 消费时补窗(`streamRead`,worker 线程)—— 阈值批量

handler 每消费 `n` 字节(`streamRead` 返回 n 前):把 `n` 通过下面的 `creditRecv` 计入 stream 与 conn 的 pending。

`creditRecv(conn, st, amt)`(可从 reader 线程的 padding 路径、或 worker 线程的消费路径调用):
- **stream 级**:持 `rx_mu`,`recv_pending += amt`;若 `recv_pending >= cfg.initial_window_size / 2`(阈值,至少 1),取出 `d = recv_pending`,`recv_window += d; recv_pending = 0`;记下待发 `(sid, d)`。释放 `rx_mu`。
- **conn 级**:持 `recv_mu`,`conn_recv_pending += amt`;若 `conn_recv_pending >= cfg.connection_window_size / 2`,取出 `dc = conn_recv_pending`,`conn_recv_window += dc; conn_recv_pending = 0`;记下待发 `(0, dc)`。释放 `recv_mu`。
- **锁外**再经 `conn.cw.frame(.window_update, …)` 发出记下的 `WINDOW_UPDATE` 帧(不在持锁时写帧)。

调用点若已持 `rx_mu`(如 `streamRead` 内、`handleData` 的 padding 路径),则内联该逻辑、遵守 `rx_mu → recv_mu` 锁序,不重入。

**阈值 = 窗口/2 的理由**:handler 持续消费时对端永不完全停等,又避免每次小读都发一帧。

**不死锁(正确的二分论证)**:handler 只在 `rx_buf` 空时阻塞。缓冲区空时,以下二者**至少一个**成立:
- **(a)** 本流累计消费已越过 ½ 阈值 → 已发过 `WINDOW_UPDATE`,对端已获新窗口;或
- **(b)** 累计消费 < ½ 阈值 → 但这意味着对端在本流上发的量也 < 半窗,即对端**仍持有正的剩余发送窗**(未耗尽),它没有被我方流控阻塞。

无论哪种,都不存在"我方等对端发、对端等我方补窗"的双向等待,故无死锁。(注意:前一版把"缓冲空"直接等同于"pending 已越阈值"是**错误**的 —— 小于半窗的小请求会被一次读空而 pending 从未越阈值;正确性来自 (b) 而非 (a)。)

## 锁序

新增 `conn.recv_mu` 为**叶子锁**:任何路径先持 `rx_mu`(或 `streams_mu → rx_mu`)再短暂取 `recv_mu`,统一 `rx_mu → recv_mu`;`recv_mu` 下不取任何其他锁,也不写帧。补窗量在锁内算好,**释放锁后**再写 `WINDOW_UPDATE`(与现有"持 send_mu 算好、锁外写帧"风格一致)。`handleData` 的连接扣减(步骤 1)在取 `streams_mu`/`rx_mu` 之前独立完成(先 `recv_mu` 再释放),不与 `rx_mu` 嵌套,避免与消费路径的 `rx_mu → recv_mu` 形成环。

> 注:步骤 1(扣减,先于 `rx_mu`)与消费路径(`rx_mu → recv_mu`)对 `recv_mu` 都是"取了就放、其下无锁",不构成 `rx_mu`↔`recv_mu` 循环等待。

## Config

- 保留 `initial_window_size: u32`(per-stream 接收窗;默认 65535;经 `SETTINGS_INITIAL_WINDOW_SIZE` 通告)。
- 新增 `connection_window_size: u32`(默认 **1 MiB = 1048576**);启动放大 connection 接收窗。取用时 clamp 到 `[65535, 0x7fff_ffff]`。
- 文档注明:per-stream 64KB 在高 RTT WAN 上受 BDP 限制会限吞吐;CDN 大上传应调大 `initial_window_size`。默认保持 RFC 保守值。

## 启动:放大 connection 接收窗

`serveConn` 发送 SETTINGS 后:令 `cw = clamp(cfg.connection_window_size)`,置 `conn.conn_recv_window = cw`;若 `cw > 65535`,在 stream 0 发 `WINDOW_UPDATE(cw - 65535)`。`recv_pending` / `conn_recv_pending` 初值 0。

## 强制(越窗)

- 连接窗被扣成负(步骤 1) → `GOAWAY(FLOW_CONTROL_ERROR)`,连接致命。
- 流窗被扣成负(步骤 3) → `RST_STREAM(FLOW_CONTROL_ERROR)`,仅该流。
这替代原 `max_request_body` 的 8 MB → `RST` 逻辑。

## 测试(用现有 socketpair + 真实 client / 裸帧脚手架)

1. **端到端背压、无 RST**:`config.initial_window_size` 设小(如 256),handler 先 `Io.sleep` 再读并 echo;真实 client 发远大于窗口的 body(如 4 KB,分片由其发送侧流控自然驱动)。断言:全部字节到达且被 echo 回、期间**无 `RST_STREAM`**——证明对端是被流控阻塞(send_window 归零)而非在旧 8 MB 处被 RST。
2. **越窗强制(stream)**:配小窗(如 100),裸帧一次性发超过窗口的 DATA(不等补窗)→ 断言收到 `RST_STREAM(FLOW_CONTROL_ERROR)`(错误码 0x3)。
3. **补窗时机**:裸 client 发一批(≤窗口)DATA 后,在 handler 消费前**不应**收到 `WINDOW_UPDATE`;handler 消费越阈值后**才**收到 `WINDOW_UPDATE`。(用一个"读到 N 字节才继续"的 handler 控制时序。)
4. **connection 越窗**(Task 2):裸帧在多个流上累计发出超过 `connection_window_size` 的 DATA → 断言 `GOAWAY(FLOW_CONTROL_ERROR)`。
5. 现有测试必须继续通过 —— 特别是 "server advertises configured SETTINGS":因启动新增 stream-0 `WINDOW_UPDATE`,确认该测试用 `readFrameOfType(.settings)` 跳过无关帧(若不是,调整为跳过)。

## 风险与缓解

- **默认行为变化**:窗口从"实际无限(自动补满)"变为有界(默认 conn 1 MiB / stream 64 KB)。这正是 #5 的目的(加背压),但可能限制此前依赖无背压的高吞吐上传 —— 已通过可配置 + 文档缓解;CDN 调大 `initial_window_size`。
- **补窗死锁**:靠"缓冲区空 ⟺ pending 越阈值"不变式排除;阈值 = 窗口/2 保证 handler 持续消费时对端不完全停等。
- **锁序**:`recv_mu` 严格叶子,`rx_mu → recv_mu` 单向;帧写在锁外。
- **padding 会计**:整帧计流控,padding 开销即刻补、data 消费时补,总补 = `fc_len`,与对端 send 侧记账精确一致。

## 落地顺序(增量、TDD)

两个 Task 都要保持连接可用、全测试绿。关键:**Task 1 只改 stream 级,connection 级保持现状(收到即发整帧 `WINDOW_UPDATE` 自动补满)**,Task 2 才把 connection 级换成跟踪式。这样中间态不会破坏连接流控。

- **Task 1(per-stream)**:
  - H2Stream 加 `recv_window`(初值 `cfg.initial_window_size`)/`recv_pending`(`rx_mu` 保护)。
  - `handleData`:**移除 stream 级的即刻 `WINDOW_UPDATE`**;**保留 connection 级的即刻 `WINDOW_UPDATE`(整帧 `fc_len`)不变**;新增 `recv_window -= fc_len` + 越窗 `RST_STREAM(FLOW_CONTROL_ERROR)`;缓存 data;`overhead` 即刻做 **stream 级** 补窗。
  - `streamRead`:消费 `n` 时做 **stream 级** 阈值批量补窗(`recv_pending`,阈值 `cfg.initial_window_size/2`,锁外发 stream `WINDOW_UPDATE`)。
  - 移除 `max_request_body` 常量及其检查。
  - 测试 1/2/3(单流背压足以覆盖,因 client 的 stream send_window = 服务端通告的 `initial_window_size`)。
- **Task 2(connection)**:
  - Connection 加 `recv_mu`/`conn_recv_window`/`conn_recv_pending`;`Config.connection_window_size`(默认 1 MiB,clamp);`serveConn` 启动放大。
  - `handleData`:把保留的即刻 connection `WINDOW_UPDATE` **替换**为 `conn_recv_window -= fc_len` + 越窗 `GOAWAY(FLOW_CONTROL_ERROR)`;`overhead` 追加 **connection 级** 补窗。**所有丢弃路径把 `fc_len` 补回连接窗**:stream 不存在、流窗越界 RST、append OOM(见"连接窗返还总不变式")。
  - `streamRead`:消费同时做 **connection 级** 阈值批量补窗(`conn_recv_pending`,阈值 `cfg.connection_window_size/2`,`rx_mu → recv_mu` 锁序,锁外发 stream-0 `WINDOW_UPDATE`)。
  - **流终止路径**(`runStream` 释放 `rx_buf` 前):把未消费残留 `rx_buf.items.len - rx_off` 补回连接窗,堵住"handler 不读 body"的泄漏。
  - 说明:批量阈值下残留 `conn_recv_pending`(< 半窗)**不是泄漏**(是待发 credit,随后续流量或流终止返还一并冲刷);泄漏特指"扣了从不返还",已由总不变式堵死。
  - 测试 4 + **新增:多流各自 handler 不读 body 并快速结束、反复很多轮,断言连接不会因连接窗被吃空而假性背压(后续流仍能正常收发)** + 回归测试 5。
