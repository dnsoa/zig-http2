# 客户端入站帧/CONTINUATION 上限 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 客户端 reader 对服务端发来的帧设上限——单帧 ≤ 16384、HEADERS+CONTINUATION 累计 ≤ 256KB;越限发 `GOAWAY(对应码)` 后 `kill()`,堵住回源到不可信源站的 DoS 面。

**Architecture:** `init` 通告 `SETTINGS_MAX_FRAME_SIZE=16384`;`readerLoop` 在 `parseHeader` 后、alloc 前拒绝 `length > 16384`;`readContinuations` 增加单帧上限(>16384)与累计上限(256KB);越限用新 `sendGoaway` helper 发 GOAWAY(last-id=0)再 kill(readContinuations 内发 GOAWAY 后返回 error,由 readerLoop 统一 kill)。

**Tech Stack:** Zig 0.16.0,`std.Io`,无第三方依赖。

**Spec:** `docs/superpowers/specs/2026-07-10-client-inbound-limits-design.md`

## Global Constraints

- Zig 0.16.0;仅用 `std`;非测试改动限于 `src/client.zig`(`proto.zig` 无需改:`frame_size_error`/`enhance_your_calm`/`set_max_frame_size`/`our_max_frame_size` 均已具备)。
- 上限均为常量:单帧 `p2.our_max_frame_size`(16384),累计 `256*1024`。越限连接致命(kill);因即将销毁连接,无需保持 HPACK 同步。
- 越限顺序:先 `sendGoaway(code)`(仅取 `write_mu` 写帧)再 `kill()`;`readContinuations` 内发 GOAWAY 后返回 error,readerLoop 的 `handle(...) catch { kill(); }` 完成 kill(不重复发)。
- 测试用 loopback(参考 keepalive 测试的 listen/connect/accept),测试线程既驱动 client、又作裸帧服务端;新增局部帧读写 helper。
- 每个任务结束跑 `zig build test --summary all` 全绿(现状 53/53 + 新增);伪 "failed command … --listen=-" 行忽略,以 "Build Summary: N/N tests passed" 为准。

---

### Task 1: 客户端入站帧大小与 CONTINUATION 上限

**Files:**
- Modify: `src/client.zig`(常量、`init` SETTINGS、`sendGoaway`、`readerLoop`、`readContinuations`)
- Test: `src/client.zig` `test` 区(helper + 3 用例)

**Interfaces (Produces):**
- 文件级常量 `max_recv_frame: u32`、`max_header_block: usize`
- `fn Client.sendGoaway(self: *Client, code: p2.ErrorCode) void`

- [ ] **Step 1: 实现**

> 说明:本任务的新用例在**旧代码上会挂起**(旧 client 要么阻塞读一个永不到来的 payload,要么吞下 CONTINUATION flood 等永不到来的 END_HEADERS),无法快速"先跑红"。故先实现、再加用例、跑绿(与本仓库同类服务端行为测试一致);评审据代码论证"无此改动即失败"。

1a. 在文件级(靠近其它 `const`,如 `reader_wake_ms` 附近)新增:

```zig
/// Max inbound frame size we accept, advertised as SETTINGS_MAX_FRAME_SIZE.
/// Equals the RFC default/minimum; we never advertise larger, so a larger frame
/// is a peer error we reject rather than allocate for.
const max_recv_frame: u32 = p2.our_max_frame_size; // 16384
/// Hard cap on one response's accumulated header block across HEADERS +
/// CONTINUATION (CVE-2024-27316 class); matches the server's bound.
const max_header_block: usize = 256 * 1024;
```

1b. `init`:把现有单条 SETTINGS 段替换为两条(ENABLE_PUSH=0 + MAX_FRAME_SIZE):

```zig
        try self.w.writeAll(p2.preface);
        // Advertise SETTINGS_ENABLE_PUSH=0 (we don't implement PUSH_PROMISE) and
        // SETTINGS_MAX_FRAME_SIZE=16384 (the largest inbound frame we accept).
        var settings: [12]u8 = undefined;
        p2.putSetting(settings[0..6], p2.set_enable_push, 0);
        p2.putSetting(settings[6..12], p2.set_max_frame_size, max_recv_frame);
        try self.writeFrame(.settings, 0, 0, &settings);
        self.reader_thread = std.Thread.spawn(.{}, readerLoop, .{self}) catch null;
```

1c. 新增 helper(放在 `writeFrame` / `writeData` 附近):

```zig
    /// Best-effort GOAWAY(last_stream_id=0, code). The client only observes
    /// peer-initiated (even/push) streams — disabled — so the last id is 0.
    fn sendGoaway(self: *Client, code: p2.ErrorCode) void {
        var p: [8]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], 0, .big);
        std.mem.writeInt(u32, p[4..8], @intFromEnum(code), .big);
        self.writeFrame(.goaway, 0, 0, &p) catch {};
    }
```

1d. `readerLoop`:`parseHeader` 之后、`alloc` 之前加帧大小上限。把:

```zig
            const fh = p2.parseHeader(&hb);
            const payload = self.gpa.alloc(u8, fh.length) catch {
                self.kill();
                return;
            };
```
改为:

```zig
            const fh = p2.parseHeader(&hb);
            if (fh.length > max_recv_frame) {
                self.sendGoaway(.frame_size_error);
                self.kill();
                return;
            }
            const payload = self.gpa.alloc(u8, fh.length) catch {
                self.kill();
                return;
            };
```

1e. `readContinuations`:加单帧上限 + 累计上限。把:

```zig
            const cf = p2.parseHeader(&hb);
            if (cf.ftype != .continuation or cf.sid != sid) return error.ProtocolError;
            const cp = try self.gpa.alloc(u8, cf.length);
```
改为:

```zig
            const cf = p2.parseHeader(&hb);
            if (cf.ftype != .continuation or cf.sid != sid) return error.ProtocolError;
            if (cf.length > max_recv_frame) {
                self.sendGoaway(.frame_size_error);
                return error.FrameSizeError;
            }
            if (block.items.len + cf.length > max_header_block) {
                self.sendGoaway(.enhance_your_calm);
                return error.ProtocolError;
            }
            const cp = try self.gpa.alloc(u8, cf.length);
```

- [ ] **Step 2: 加 helper 与 3 个用例**

在 `test` 区(现有 client 测试附近)追加帧读写 helper:

```zig
const CtFrame = struct {
    hdr: p2.ParsedHeader,
    payload: []u8,
    fn deinit(self: *CtFrame, a: std.mem.Allocator) void {
        a.free(self.payload);
    }
};
fn ctRead(a: std.mem.Allocator, r: *Io.Reader) !CtFrame {
    var hb: [9]u8 = undefined;
    try r.readSliceAll(&hb);
    const hdr = p2.parseHeader(&hb);
    const payload = try a.alloc(u8, hdr.length);
    errdefer a.free(payload);
    if (payload.len > 0) try r.readSliceAll(payload);
    return .{ .hdr = hdr, .payload = payload };
}
/// Reads frames until a GOAWAY, returns its error code (payload[4..8]).
fn ctReadGoawayCode(a: std.mem.Allocator, r: *Io.Reader) !u32 {
    while (true) {
        var f = try ctRead(a, r);
        defer f.deinit(a);
        if (f.hdr.ftype == .goaway) return std.mem.readInt(u32, f.payload[0..][4..8], .big);
    }
}
fn ctWrite(w: *Io.Writer, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
    var hb: [9]u8 = undefined;
    p2.putHeader(&hb, payload.len, ftype, flags, sid);
    try w.writeAll(&hb);
    if (payload.len > 0) try w.writeAll(payload);
    try w.flush();
}
/// Writes only a 9-byte frame header declaring `length` (no payload) — used to
/// trigger the client's size check before it allocates/reads the body.
fn ctWriteHeaderOnly(w: *Io.Writer, ftype: p2.FrameType, sid: u31, length: usize) !void {
    var hb: [9]u8 = undefined;
    p2.putHeader(&hb, length, ftype, 0, sid);
    try w.writeAll(&hb);
    try w.flush();
}
/// Common setup: loopback client + raw "server" side; consumes the client's
/// preface+SETTINGS and sends SETTINGS+ack. Returns nothing; caller uses the
/// captured streams. (Kept inline in each test for clarity — see below.)
```

然后三个用例(每个自带 loopback 建连 + 握手;注意 `net`/`testing`/`Client`/`p2` 均在作用域):

```zig
test "client rejects an oversized inbound frame with GOAWAY(FRAME_SIZE_ERROR)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [20000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface); // client SETTINGS
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    const s = try client.openStream(.{ .path = "/x" }, false);
    // A DATA frame declaring length 20000 (> 16384). Header only; the client
    // must reject on the header, before allocating/reading the body.
    try ctWriteHeaderOnly(&asw.interface, .data, 1, 20000);

    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.frame_size_error)), code);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.ConnectionClosed, s.readEvent(arena.allocator()));
}

test "client rejects a CONTINUATION flood with GOAWAY(ENHANCE_YOUR_CALM)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [20000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    // HEADERS (sid 1, END_HEADERS clear) + CONTINUATION frames of 16384 filler
    // bytes each until the accumulated block crosses 256 KiB. 100 + 16*16384 =
    // 262244 > 262144, so the 16th CONTINUATION trips the cap. Content is never
    // decoded (we hit the cap first), so filler is fine.
    var filler: [16384]u8 = @splat('x');
    try ctWrite(&asw.interface, .headers, 0, 1, filler[0..100]);
    var i: usize = 0;
    while (i < 16) : (i += 1) try ctWrite(&asw.interface, .continuation, 0, 1, &filler);

    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.enhance_your_calm)), code);
}

test "client rejects an oversized CONTINUATION with GOAWAY(FRAME_SIZE_ERROR)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    var filler: [100]u8 = @splat('x');
    try ctWrite(&asw.interface, .headers, 0, 1, &filler); // no END_HEADERS
    // A CONTINUATION declaring length 20000 (> 16384). Header only.
    try ctWriteHeaderOnly(&asw.interface, .continuation, 1, 20000);

    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.frame_size_error)), code);
}
```

- [ ] **Step 3: 跑全套测试**

Run: `zig build test --summary all`
Expected: PASS —— 现有 53 + 3 新用例 = 56/56。若某用例挂起,说明对应上限未生效(旧行为),检查 1d/1e。用 `zig fmt --check src/client.zig` 确认格式,必要时 `zig fmt`。

- [ ] **Step 4: Commit**

```bash
git add src/client.zig
git commit -m "client: cap inbound frame size and CONTINUATION accumulation"
```

---

## Self-Review

**Spec coverage:**
- 常量 `max_recv_frame`(16384)/`max_header_block`(256KB)→ 1a ✓
- `init` 通告 `MAX_FRAME_SIZE` → 1b ✓
- `sendGoaway`(last-id=0)→ 1c ✓
- `readerLoop` 帧大小上限 + GOAWAY(frame_size_error)+kill → 1d ✓
- `readContinuations` 单帧上限(frame_size_error)+ 累计上限(enhance_your_calm)+ GOAWAY-then-return-error → 1e ✓
- 测试:超大帧 / CONTINUATION flood / 超大 CONTINUATION + 回归 → Step 2/3 ✓

**Placeholder scan:** 无 TBD;每步完整可粘贴代码。

**Type consistency:**
- `sendGoaway(self, code: p2.ErrorCode)`、`max_recv_frame: u32`、`max_header_block: usize` 定义与引用一致。
- `readerLoop` 用 `fh.length`(u32)与 `max_recv_frame`(u32)比较;`readContinuations` 用 `block.items.len`(usize)+`cf.length`(u32→加法提升)与 `max_header_block`(usize)比较 —— 注意 `block.items.len + cf.length` 需保证不溢出:`cf.length ≤ 16384`(上一检查已保证),`block` 受 256KB 约束,和远小于 usize 上限,安全。
- 测试 helper `ctRead`/`ctReadGoawayCode`/`ctWrite`/`ctWriteHeaderOnly` 与 `CtFrame` 自洽;`p2.putHeader(&hb, length: usize, ...)`、`p2.parseHeader`、`p2.ErrorCode`、`net`/`Io` 均为现有 API。
