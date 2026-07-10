# 设计:接受请求 trailers,不再误杀连接

- 日期:2026-07-10
- 对应 review 项:🟡「请求 trailers 会误杀连接」
- 目标库:`zig-http2`(gRPC / 自研 CDN 的 HTTP/2 底座)

## 背景与 bug

`handleHeaders`(`src/server.zig:930-934`)对**任何** `fh.sid <= conn.last_stream_id`(或偶数 id)的 HEADERS 一律:

```zig
if (fh.sid <= conn.last_stream_id or fh.sid % 2 == 0) {
    sendGoaway(conn, .protocol_error);
    return error.ProtocolError;
}
```

而合法的 HTTP/2 **请求 trailers**(RFC 7540 §8.1)= 已开流上的**第二个 HEADERS 帧**(带 END_STREAM,承载 trailing 字段),其 `fh.sid == last_stream_id`,于是命中该分支 → `GOAWAY(protocol_error)` → **整条连接被杀**。

影响:gRPC 客户端不发请求 trailers(HEADERS + DATA + END_STREAM-on-DATA),故 gRPC 不受影响;但任意 HTTP/2 客户端合法地发 trailing HEADERS 就会断连 —— 对通用 CDN 是真实的正确性/一致性缺陷。

## 决策(已与调用方确认)

- **接受并丢弃 trailer 字段**(最小正确):解码 trailing HEADERS(保 HPACK 同步)、校验、置 body-EOF,但**不把 trailer 字段暴露给 handler**(gRPC/CDN 无此需求;暴露需跨线程 API,留作后续)。
- **已关闭/idle 流上的 HEADERS 软化为 `RST_STREAM(STREAM_CLOSED)`**,不再 `GOAWAY`(盖住"handler 提前完成 → 流被移除 → 客户端随后发 trailer"的竞态)。

## 已核实锚点

- `handleHeaders` 在**单一 reader 线程**上运行并做 HPACK 解码(`conn.decoder.decode`),保证按 wire 顺序解码。
- 新流解码用 `st.arena()`(worker 尚未 spawn,reader 独占 `st`)。**trailing/closed 路径的 worker 已在并发运行、持有 `st.arena()`**,故这些路径必须解码到**独立临时 arena**,不得碰 `st.arena()`。
- `handleData`(`src/server.zig`)已确立"持 `streams_mu` 跨越对 `s` 的整个操作,防 worker 在 `removeStream` 释放它"的防护;锁序 `streams_mu → rx_mu`。
- `rx_eof` + `rx_cond.broadcast`(持 `rx_mu`)是现有的"body 结束"通知机制(DATA 的 END_STREAM 用它)。
- `proto.ErrorCode` 现无 `STREAM_CLOSED`(0x5);需新增。
- worker 只做 `removeStream`(移除),从不新增流 → "不在 map 且 id > last 且奇数" 的分类是稳定的(无竞态);只有"在 map"可能在动作前变为"已移除"。

## 变更

### 1) `proto.zig`:新增错误码
`ErrorCode` 加 `stream_closed = 0x5`(RFC 7540 §7)。

### 2) `handleHeaders`:HEADERS 流 id 分类

在组装完整 block(含 CONTINUATION,现 `src/server.zig:928` 之后)、当前"New stream id must be odd and strictly increasing"检查(931)**之前**,插入分类:

```
// 初次路由(仅用于判定;真正动作时在锁下重取):
conn.streams_mu.lock(); const open = conn.streams.contains(fh.sid); conn.streams_mu.unlock();

if (open) return handleTrailingHeaders(conn, fh, block.items);   // 已开流上的第二个 HEADERS

if (fh.sid % 2 == 0) { sendGoaway(conn, .protocol_error); return error.ProtocolError; } // 客户端不得用偶数 id

if (fh.sid <= conn.last_stream_id) {
    // 奇数、<= last、不在 map = 已关闭/idle 流。必须解码以保 HPACK 同步,再 RST(不杀连接)。
    decodeDiscard(conn, block.items) catch { sendGoaway(conn, .protocol_error); return error.ProtocolError; };
    rstStreamCode(conn, fh.sid, .stream_closed);
    return;
}

// 新流:沿用现有逻辑(设 last_stream_id、并发上限、建 st、解码到 st.arena、spawn worker)。
conn.last_stream_id = fh.sid;
... 现有新流代码 ...
```

`decodeDiscard(conn, block)`:在临时 `ArenaAllocator`(gpa 背,`defer deinit`)上 `conn.decoder.decode`,丢弃结果;仅用于推进 HPACK 动态表。解码错误向上抛(调用点转 `GOAWAY(protocol_error)`)。

### 3) `handleTrailingHeaders(conn, fh, block) !void`

```
// (a) 解码到临时 arena(reader 线程;保 HPACK 同步)。不得用 st.arena()——worker 并发持有。
var tmp = ArenaAllocator.init(conn.gpa); defer tmp.deinit();
const decoded = conn.decoder.decode(tmp.allocator(), block) catch {
    sendGoaway(conn, .protocol_error); return error.ProtocolError; // HPACK 崩坏 = 连接致命
};

// (b) 预判合法性(不依赖流状态):
var invalid_code: ?ErrorCode = null;
if (fh.flags & flag_end_stream == 0) invalid_code = .protocol_error;         // trailers 必须结束流
else for (decoded) |h| if (h.name.len > 0 and h.name[0] == ':') { invalid_code = .protocol_error; break; }; // trailers 不得含伪首部

// (c) 在锁下重取并按最新状态动作(初次路由到此,worker 可能已 removeStream 释放该流):
conn.streams_mu.lock();
const s = conn.streams.get(fh.sid) orelse {
    conn.streams_mu.unlock();
    rstStreamCode(conn, fh.sid, .stream_closed);   // 已被移除 → 纯回 STREAM_CLOSED,不碰流对象
    return;
};
s.rx_mu.lock();
// 活流上需要 RST 的情形(rst_code != null):
//   - 已收过 END_STREAM(half-closed remote,RFC §5.1)→ STREAM_CLOSED;
//   - 否则 trailers 非法(无 END_STREAM / 含伪首部)→ invalid_code(protocol_error)。
const rst_code: ?ErrorCode = if (s.rx_eof) .stream_closed else invalid_code;
if (rst_code) |code| {
    // 流错误:必须一致地终止本地 worker —— 与 resetStream 语义对齐,
    // 否则会"已对该流发 RST,却仍在其上继续写 HEADERS/DATA"。
    // 置 reset + 唤醒 rx 与 send 两侧,worker 从 streamRead/sendBody 得到
    // StreamReset 后干净退出;runStream 见 reset 便不再重复 RST。
    s.reset.store(true, .release);
    s.rx_cond.broadcast(conn.io);
    s.rx_mu.unlock();
    conn.streams_mu.unlock();
    conn.wakeSenders();                 // 关键:唤醒可能阻塞在 send_window 上的 worker(rx_cond 唤不到发送侧)
    rstStreamCode(conn, fh.sid, code);
    return;
}
// 合法 trailers:置 body-EOF,丢弃字段(不 reset;handler 正常读到 EOF 并写响应)。
s.rx_eof = true;
s.rx_cond.broadcast(conn.io);
s.rx_mu.unlock();
conn.streams_mu.unlock();
```

不动 `last_stream_id`、不开新流、不 spawn worker。锁序与 `resetStream` 一致:先释放 `rx_mu`/`streams_mu`,再 `wakeSenders()`(取 `send_mu`)、再写 RST 帧,避免锁嵌套。

## 语义小结

| 到达的 HEADERS | 旧行为 | 新行为 |
|---|---|---|
| 已开流 + END_STREAM + 无伪首部 | GOAWAY | 接受为 trailers:置 body-EOF,丢字段 |
| 已开流 + 无 END_STREAM | GOAWAY | `RST_STREAM(PROTOCOL_ERROR)` + 终止本地 worker(reset+唤醒两侧) |
| 已开流 + 含伪首部 | GOAWAY | `RST_STREAM(PROTOCOL_ERROR)` + 终止本地 worker(reset+唤醒两侧) |
| 已开流但已收过 END_STREAM | GOAWAY | `RST_STREAM(STREAM_CLOSED)` + 终止本地 worker(reset+唤醒两侧) |
| 已关闭/移除的奇数 id(≤ last) | GOAWAY | 解码保同步 + `RST_STREAM(STREAM_CLOSED)`(不碰流对象) |
| 偶数 id | GOAWAY | GOAWAY(protocol_error)(不变) |
| 新的奇数 id(> last) | 新流 | 新流(不变) |

## 测试(raw 帧,现有 socketpair 脚手架)

1. **请求 trailers 被接受、连接存活(核心,RED)**:HEADERS(sid 1,END_HEADERS,**无** END_STREAM)+ DATA(sid 1,"body",无 ES)+ trailing HEADERS(sid 1,END_HEADERS|END_STREAM,块用 `hpack.Encoder.encodeTrailers` 编码一个字段如 `x-sum: 1`)。handler = 读满 body 并 echo 的 `flowEchoHandler`。断言:收到正常 200 响应 + body 回显 + 响应 END_STREAM,**全程无 GOAWAY**。旧代码在 trailing HEADERS 处 GOAWAY → 该用例失败(真 RED)。
2. **trailers 无 END_STREAM → 该流 RST(protocol_error)**:同上但第二个 HEADERS 不带 END_STREAM;断言 `RST_STREAM` sid 1 code 0x1。
3. **trailers 含伪首部 → 该流 RST(protocol_error)**:trailing 块含 `:method`(用 `encodeRequest` 造含伪首部的块,或手工字节);断言 `RST_STREAM` sid 1 code 0x1。
4. **已关闭流上的 HEADERS → RST(STREAM_CLOSED) 而非 GOAWAY**:先发 bodyless HEADERS(sid 1,END_STREAM)跑完并读完响应,再发一个 HEADERS(sid 1);断言 `RST_STREAM` sid 1 code 0x5,无 GOAWAY。(此刻流或已被移除、或仍在 map 但 `rx_eof` 已置——两路都归 STREAM_CLOSED,故对竞态稳健。)
5. 现有全套回归(尤其 raw round-trip、gRPC echo、finish 幂等)。

## 风险与缓解

- **HPACK 同步**:trailing / closed 路径必须解码(即便随后 RST/丢弃),否则动态表失步、后续所有 header 解码崩坏 —— 设计已在两处强制解码;解码失败一律 `GOAWAY(protocol_error)`。
- **并发/生命周期**:初次路由的 `contains` 只用于分流;真正动作在 `streams_mu` 下重取,流已被移除则走 STREAM_CLOSED —— 复用 `handleData` 的 `streams_mu → rx_mu` 防护,无 use-after-free。
- **临时 arena**:trailing/closed 路径的解码只落在临时 arena,`defer deinit` 立即回收;绝不触碰 worker 持有的 `st.arena()`。
- **RST 活流必须终止本地 worker(评审补强)**:对仍在 map 的活流发 RST 时,只 `rx_cond.broadcast` 无法唤醒阻塞在 `sendBody`(等 `send_window`)的 worker —— 它只在 `send_cond` 被唤醒后才重查 `reset`。必须置 `reset` + `rx_cond.broadcast` + `wakeSenders()`(与 `resetStream` 三件套一致),否则会"reader 已发 RST、本地 worker 仍卡着甚至继续在已 RST 的流上写帧"。仅"锁下重取已不在 map"那路无 worker 可终止,纯回 STREAM_CLOSED。
- **一致性取舍**:情况 4 对"idle 跳号 id"也回 `RST(STREAM_CLOSED)` 而非 GOAWAY,比严格 h2spec 宽松;换取 CDN 场景不因一个坏流/迟到 trailer 断掉整连接。已在决策中确认。

## 落地(单 Task、TDD)

单 Task:`proto.zig` 加 `stream_closed`;`handleHeaders` 插入分类 + `decodeDiscard`;新增 `handleTrailingHeaders`;测试 1–4 + 回归 5。先写测试(2/3/4 可先建基线;1 是 RED,旧代码 GOAWAY 会让其失败/连接断),再实现,跑全绿。
