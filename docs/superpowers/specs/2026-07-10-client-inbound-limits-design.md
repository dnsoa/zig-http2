# 设计:客户端入站帧大小 / CONTINUATION 上限

- 日期:2026-07-10
- 对应 review 项:🟡「client 入站帧大小 / CONTINUATION 无上限」
- 目标库:`zig-http2`(gRPC / 自研 CDN 的 HTTP/2 底座)

## 背景与 bug

`src/client.zig` 的 reader 线程对服务端发来的帧不设上限:

1. **帧大小**:`readerLoop`(`client.zig:353-358`)读完 9 字节帧头后直接 `self.gpa.alloc(u8, fh.length)`,`fh.length` 可达 2²⁴−1(~16 MB)。客户端从不通告也不强制 `SETTINGS_MAX_FRAME_SIZE`,恶意/有 bug 的服务端可反复发超大帧。
2. **CONTINUATION 累计**:`readContinuations`(`client.zig:540-551`)循环拉 CONTINUATION 直到 END_HEADERS,**对累计 block 大小无任何上限**,且每个 `cf.length` 也未校验就 alloc。恶意服务端可无限发 CONTINUATION 撑爆内存(CVE-2024-27316 一类 —— 服务端已用 `max_header_block_bytes` 防住,客户端没有)。

对 CDN 回源到不可信/有 bug 的源站,这是真实 DoS 面。

## 决策(已确认)

- **帧大小上限 = 常量 16384**(`p2.our_max_frame_size`,RFC 默认/最小值):`init` 通告 `SETTINGS_MAX_FRAME_SIZE=16384`,reader 拒绝 `length > 16384` 的帧。不新增可配置字段(如需大帧后续再加)。
- **CONTINUATION 累计上限 = 256 KB 常量**(与服务端 `max_header_block_bytes` 对齐)。
- **越限时**:发 `GOAWAY(对应错误码)` 后 `kill()`(与服务端行为对称,比裸 kill 更礼貌,让源站知道原因)。

## 已核实锚点

- `init`(`client.zig`)现发 preface + 一条含 `ENABLE_PUSH=0` 的 SETTINGS(6 字节)。`p2` 有 `set_enable_push`/`set_max_frame_size`/`putSetting`/`our_max_frame_size=16384`。
- `readerLoop` 读 9 字节帧头 → `parseHeader` → alloc `fh.length` → 读 payload → `handle`;出错走 `self.kill(); return`。**帧大小检查应在 `parseHeader` 之后、alloc 之前**。
- `readContinuations` 在 `handle` 的 `.headers` 分支中被 `try` 调用;其返回的 error 经 `handle` 上抛到 readerLoop 的 `self.handle(...) catch { self.kill(); return; }`。故在 `readContinuations` 内发 GOAWAY 后返回 error,readerLoop 便会 kill(不重复发)。
- `ErrorCode` 已有 `frame_size_error`(0x6)、`enhance_your_calm`(0xb);无需改 `proto.zig`。
- 客户端 GOAWAY 的 last-stream-id 指"已处理的对端发起(偶数/push)流";push 已禁用,故取 0。

## 变更(全部在 `src/client.zig`)

### 1) 常量
```zig
/// Max inbound frame size we accept (advertised as SETTINGS_MAX_FRAME_SIZE).
/// Equals the RFC default/minimum; we never advertise larger, so larger frames
/// are rejected. (Matches p2.our_max_frame_size.)
const max_recv_frame: u32 = p2.our_max_frame_size; // 16384
/// Hard cap on one response's accumulated header block across HEADERS +
/// CONTINUATION (CVE-2024-27316 class). Matches the server's bound.
const max_header_block: usize = 256 * 1024;
```

### 2) `init`:通告 MAX_FRAME_SIZE
把现有单条 SETTINGS 改为两条(ENABLE_PUSH=0 + MAX_FRAME_SIZE=16384):
```zig
var settings: [12]u8 = undefined;
p2.putSetting(settings[0..6], p2.set_enable_push, 0);
p2.putSetting(settings[6..12], p2.set_max_frame_size, max_recv_frame);
try self.writeFrame(.settings, 0, 0, &settings);
```

### 3) GOAWAY helper
```zig
/// Best-effort GOAWAY(last_stream_id=0, code). Client only sees peer-initiated
/// (even/push) streams, which are disabled, so last id is 0.
fn sendGoaway(self: *Client, code: p2.ErrorCode) void {
    var p: [8]u8 = undefined;
    std.mem.writeInt(u32, p[0..4], 0, .big);
    std.mem.writeInt(u32, p[4..8], @intFromEnum(code), .big);
    self.writeFrame(.goaway, 0, 0, &p) catch {};
}
```

### 4) `readerLoop`:帧大小上限
`parseHeader` 之后、`alloc` 之前:
```zig
const fh = p2.parseHeader(&hb);
if (fh.length > max_recv_frame) {
    self.sendGoaway(.frame_size_error);
    self.kill();
    return;
}
const payload = self.gpa.alloc(u8, fh.length) catch { ... };
```

### 5) `readContinuations`:每帧大小 + 累计上限
```zig
const cf = p2.parseHeader(&hb);
if (cf.ftype != .continuation or cf.sid != sid) return error.ProtocolError;
if (cf.length > max_recv_frame) {                       // 单帧超限
    self.sendGoaway(.frame_size_error);
    return error.FrameSizeError;
}
if (block.items.len + cf.length > max_header_block) {   // 累计超限
    self.sendGoaway(.enhance_your_calm);
    return error.ProtocolError;
}
const cp = try self.gpa.alloc(u8, cf.length);
... 现有读取 + append ...
```

> 初始 HEADERS 帧的 payload 已被 (4) 的 readerLoop 上限约束(≤16384);CONTINUATION 由 (5) 独立约束单帧与累计。

## 测试(client.zig 测试区,loopback + 裸帧服务端)

用现有 loopback 模式(参考 keepalive 测试:listen → connect(客户端侧)→ accept(测试作为裸服务端侧)),测试侧读走客户端的 preface + SETTINGS,发 SETTINGS+ack,再发恶意帧,并读回客户端发出的 GOAWAY。

1. **超大帧 → GOAWAY(frame_size_error) + 连接死**:测试侧只发一个 9 字节帧头,length=20000(> 16384),不发 payload。断言:读到客户端发出的 `GOAWAY`,code=0x6;且客户端上已开 stream 的 `readEvent` 返回 `error.ConnectionClosed`。(旧代码会 alloc 20000 并尝试读满 → 不拒绝。)
2. **CONTINUATION 累计超限 → GOAWAY(enhance_your_calm)**:发 HEADERS(sid 1,END_HEADERS 清零,少量填充字节)+ 若干 CONTINUATION(每个 16384 填充字节),累计越过 256 KB(如 17×16384=278528)。断言:客户端发出 `GOAWAY` code=0xb。
3. **单个 CONTINUATION 超限 → GOAWAY(frame_size_error)**:发 HEADERS(no END_HEADERS)+ 一个 CONTINUATION 帧头 length=20000(不发 payload)。断言:客户端 `GOAWAY` code=0x6。
4. 现有 client 测试回归(keepalive、cancel、multiplex、close 等)。

## 风险与缓解

- **通告与强制一致**:通告 16384 且拒绝 >16384,与对端认知一致;不会误拒合规源站(默认就是 16384)。
- **GOAWAY 后 kill 的顺序**:helper 只发帧(取 `write_mu`),与 reader 读路径无锁交叠;readContinuations 发 GOAWAY 后返回 error,由 readerLoop 统一 kill,不重复发 GOAWAY。
- **测试确定性**:超大帧/单帧超限只发帧头即可触发拒绝(客户端在 alloc/读 payload 前就判);累计超限需实际发 ~278 KB CONTINUATION 数据,量可控。
- **HPACK 同步**:这些路径都是**连接致命**(kill),连接即将销毁,无需保持解码器同步(与"保留连接却带 block"的路径不同)。

## 落地(单 Task、TDD)

单 Task:常量 + `init` 通告 + `sendGoaway` + `readerLoop` 帧上限 + `readContinuations` 双上限;测试 1/2/3 + 回归 4。测试先行(旧代码不拒绝 → 三个用例因等不到 GOAWAY 而失败/超时,构造成读客户端输出遇 EOF 或读不到 GOAWAY),再实现,跑全绿。
