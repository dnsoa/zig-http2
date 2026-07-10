# 入站流控背压(credit-on-consume)Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 服务端入站流控从"收到即补满(无背压)"改为"收到即扣减、消费才补窗",双层(per-stream + connection),慢 handler 自然对快上传方施加背压而非在 8MB 处被 RST。

**Architecture:** 服务端为每个流跟踪接收窗 `recv_window`(初值 = 通告的 `SETTINGS_INITIAL_WINDOW_SIZE`),连接跟踪 `conn_recv_window`(RFC 初值 65535,配置更大时启动放大)。`handleData` 收到 DATA 只扣减 + 越窗强制(stream→`RST`,connection→`GOAWAY`);`streamRead` 消费时按量补窗(阈值批量 `WINDOW_UPDATE`);流终止 / 丢弃路径把未消费字节的连接额度返还,杜绝泄漏。

**Tech Stack:** Zig 0.16.0,`std.Io`(`Io.Mutex`/`Io.Condition`/`Io.Group`),无第三方依赖。

**Spec:** `docs/superpowers/specs/2026-07-10-inbound-flow-control-design.md`

## Global Constraints

- Zig `0.16.0`;仅用 `std`,零第三方依赖;所有非测试改动限于 `src/server.zig`。
- 传输层无关:`server.zig` 非测试代码不得引入 TLS/socket。
- 测试用 `testing.allocator`(自带泄漏检测)+ 现有 socketpair 脚手架(`newSocketPair`/`serveRawH2OnFd`/`peerStream`/`readFrameAlloc`/`readFrameOfType`/`writeFrame`);无真实网络。
- 流控长度按**整帧 payload**(含 pad 字节 + padding)计。窗口值 ∈ `[0, 2^31-1]`;连接窗初值固定 65535(RFC),仅可经 stream-0 `WINDOW_UPDATE` 放大。
- **连接窗返还总不变式**(见 spec):每份从 `conn_recv_window` 扣掉的 `fc_len` 必须恰好返还一次 —— 消费时(`streamRead`)、流终止时(未消费残留)、或丢弃时(整帧就地);否则连接窗被吃空 → 假性背压。
- 锁序:`recv_mu` 为叶子锁;统一 `rx_mu → recv_mu`;`recv_mu` 下不取其他锁、不写帧;补窗量在锁内算好、锁外再写 `WINDOW_UPDATE`。
- 每个任务结束跑 `zig build test --summary all`,必须全绿(现状 44/44 + 本任务新增用例);`zig build test` 会打印一行伪 "failed command … --listen=-",以 "Build Summary: N/N tests passed" / "test success" 为准。

---

### Task 1: per-stream 入站流控(credit-on-consume + 越窗 RST)

只改 stream 级;**connection 级保持现状**(`handleData` 收到 DATA 仍即刻发整帧连接 `WINDOW_UPDATE` 自动补满),Task 2 才改。移除 8MB `max_request_body`。

**Files:**
- Modify: `src/server.zig`
  - `H2Stream`:加 `recv_window`/`recv_pending`(rx_* 字段附近)
  - 加 `creditStreamLocked` 方法 + 模块级 `sendWindowUpdate` helper
  - `streamRead`:消费时补窗(整段重写)
  - `handleData`:去掉即刻 stream `WINDOW_UPDATE`;加 stream 扣减 + 越窗 `RST` + padding 即刻补;移除 8MB 检查
  - `handleHeaders`:流创建处初始化 `recv_window`
  - 删除 `max_request_body` 常量
- Test: `src/server.zig` `test` 区

**Interfaces (Produces):**
- `H2Stream.recv_window: i64` / `H2Stream.recv_pending: i64`(`rx_mu` 保护)
- `fn H2Stream.creditStreamLocked(self: *H2Stream, amt: i64) i64` —— 持 `rx_mu` 调用;累加 `amt` 到 `recv_pending`,越过 `cfg.initial_window_size/2` 阈值则把累计并入 `recv_window`、返回待发 `WINDOW_UPDATE` 增量(否则 0)
- `fn sendWindowUpdate(conn: *Connection, sid: u31, incr: i64) void` —— 锁外发一个 `WINDOW_UPDATE(incr)` 帧(`incr>0`)

- [ ] **Step 1: 写特征测试 B、C(在当前代码上应通过,建立基线)**

在 `test` 区末尾追加(先加不会 hang 的 B、C;RED 用例 A 与实现一起加,见 Step 3 说明):

```zig
/// Reads the full request body in small chunks and echoes each — exercises
/// many credit rounds under a small window.
fn flowEchoHandler(ctx: *types.Context) anyerror!void {
    ctx.res.status(200);
    try ctx.res.header("content-type", "application/octet-stream");
    if (ctx.body_reader) |br| {
        var tmp: [64]u8 = undefined;
        while (true) {
            const n = try br.read(&tmp);
            if (n == 0) break;
            try ctx.res.write(tmp[0..n]);
        }
    }
    try ctx.res.finish();
}

test "h2: small-window body streams end-to-end without RST (credit on consume)" {
    const client_mod = @import("client.zig");
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = flowEchoHandler,
        .config = .{ .initial_window_size = 256 }, // small stream window
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    var client: client_mod.Client = undefined;
    try client.init(testing.io, testing.allocator, &reader.interface, &writer.interface);
    defer client.deinit();

    // Body larger than the window → forces several credit rounds.
    var body: [1024]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const s = try client.openStream(.{ .path = "/echo", .method = "POST" }, false);
    try s.send(&body, true);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var got = std.ArrayList(u8).empty;
    defer got.deinit(testing.allocator);
    while (true) {
        switch (try s.readEvent(arena)) {
            .data => |d| {
                try got.appendSlice(testing.allocator, d.payload);
                if (d.end_stream) break;
            },
            .headers => |h| if (h.end_stream) break,
            .rst, .goaway => return error.UnexpectedStreamEnd, // backpressure must not RST
        }
    }
    try testing.expectEqualSlices(u8, &body, got.items);
    s.close();
}

test "h2: server emits a stream WINDOW_UPDATE after the handler consumes" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = flowEchoHandler,
        .config = .{ .initial_window_size = 256 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameOfType(testing.allocator, &reader.interface, .settings);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    // HEADERS (no END_STREAM) then a full-window DATA frame; handler drains it,
    // so the server must credit the stream back via a WINDOW_UPDATE.
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);
    var payload: [256]u8 = @splat('x');
    try writeFrame(&writer.interface, .data, 0, 1, &payload);

    var wu = try readFrameOfType(testing.allocator, &reader.interface, .window_update);
    defer wu.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), wu.header.sid); // stream-level credit
    const incr = std.mem.readInt(u32, wu.payload[0..4], .big) & 0x7fff_ffff;
    try testing.expect(incr > 0);
}
```

- [ ] **Step 2: 跑测试确认 B、C 在当前代码上通过(基线)**

Run: `zig build test --summary all`
Expected: PASS。B/C 在旧代码(即刻补满)下也应绿:B 的小 body 不会触到 8MB;C 里旧代码收到 DATA 即发 stream WINDOW_UPDATE(sid 1)。它们锁定"基本流式 + stream WU 存在"这一语义,防止重构把它做丢。

- [ ] **Step 3: 实现 Task 1**

3a. `H2Stream` 里在 `rx_eof: bool = false,` 之后加字段:

```zig
    /// Inbound (receive) flow-control window: bytes the peer may still send on
    /// this stream. Initialized to the advertised SETTINGS_INITIAL_WINDOW_SIZE;
    /// decremented on receipt, credited back as the handler consumes. rx_mu.
    recv_window: i64 = 0,
    /// Consumed-but-not-yet-acknowledged bytes, batched into a WINDOW_UPDATE
    /// once past half the initial window. rx_mu.
    recv_pending: i64 = 0,
```

3b. 在 `fn bodyReader` 之前加方法:

```zig
    /// rx_mu held. Records `amt` consumed/acknowledged bytes; returns the
    /// WINDOW_UPDATE increment to emit for this stream (0 if below threshold).
    fn creditStreamLocked(self: *H2Stream, amt: i64) i64 {
        self.recv_pending += amt;
        const threshold = @max(@as(i64, 1), @as(i64, self.conn.srv.config.initial_window_size) / 2);
        if (self.recv_pending >= threshold) {
            const d = self.recv_pending;
            self.recv_window += d;
            self.recv_pending = 0;
            return d;
        }
        return 0;
    }
```

3c. 在 `fn rstStreamCode` 之后(或 helper 区)加模块级函数:

```zig
/// Emits a single WINDOW_UPDATE frame (increment > 0). Best-effort; window
/// values are <= 2^31-1 so `incr` fits in the 31-bit field.
fn sendWindowUpdate(conn: *Connection, sid: u31, incr: i64) void {
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, @intCast(incr & 0x7fff_ffff), .big);
    conn.cw.frame(.window_update, 0, sid, &wu) catch {};
}
```

3d. 整段重写 `streamRead`(改为消费时补窗;不再用 `defer` 统一 unlock,以便释放锁后再写帧):

```zig
    fn streamRead(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *H2Stream = @alignCast(@ptrCast(ctx));
        const conn = self.conn;
        self.rx_mu.lockUncancelable(conn.io);
        while (true) {
            if (self.timed_out.load(.acquire)) {
                self.rx_mu.unlock(conn.io);
                return error.DeadlineExceeded;
            }
            if (self.reset.load(.acquire) or conn.closing.load(.acquire)) {
                self.rx_mu.unlock(conn.io);
                return error.StreamReset;
            }
            const avail = self.rx_buf.items.len - self.rx_off;
            if (avail > 0) {
                const n = @min(avail, buf.len);
                @memcpy(buf[0..n], self.rx_buf.items[self.rx_off..][0..n]);
                self.rx_off += n;
                if (self.rx_off == self.rx_buf.items.len) {
                    self.rx_buf.clearRetainingCapacity();
                    self.rx_off = 0;
                }
                // Credit the stream flow-control window for consumed bytes.
                const d = self.creditStreamLocked(@intCast(n));
                self.rx_mu.unlock(conn.io);
                if (d > 0) sendWindowUpdate(conn, self.id, d);
                return n;
            }
            if (self.rx_eof) {
                self.rx_mu.unlock(conn.io);
                return 0;
            }
            self.rx_cond.waitUncancelable(conn.io, &self.rx_mu);
        }
    }
```

3e. `handleData`:把即刻补窗那段(注释 "Replenish flow-control windows …" 的 `if (payload.len > 0) { … }` 块)替换为**仅**连接级即刻补满(Task 2 再改连接级):

```zig
    // Connection-level flow control still auto-replenishes here (converted to
    // tracked crediting in Task 2). Stream-level is credited on consumption
    // (streamRead), so no stream WINDOW_UPDATE here. Padding counts toward flow
    // control, so replenish the full frame length at the connection level.
    if (payload.len > 0) {
        const amt: u31 = @intCast(@min(payload.len, std.math.maxInt(u31)));
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, @as(u32, amt), .big);
        conn.cw.frame(.window_update, 0, 0, &wu) catch {}; // connection-level
    }
```

3f. `handleData` 的投递段:把 `max_request_body` 检查替换为 stream 窗扣减 + 越窗 `RST`,并在缓存成功后即刻补 padding 开销。将现有从 `s.rx_mu.lockUncancelable` 到 `conn.streams_mu.unlock` + `return true` 的整段替换为:

```zig
    s.rx_mu.lockUncancelable(conn.io);
    // Inbound stream flow control: deduct the full frame length (padding counts).
    const fc_len: i64 = @intCast(payload.len);
    s.recv_window -= fc_len;
    if (s.recv_window < 0) {
        // Peer exceeded the window we advertised: reset just this stream.
        s.reset.store(true, .release);
        s.rx_cond.broadcast(conn.io);
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        rstStreamCode(conn, fh.sid, .flow_control_error);
        return true;
    }
    const append_failed = data.len > 0 and blk: {
        s.rx_buf.appendSlice(conn.gpa, data) catch break :blk true;
        break :blk false;
    };
    if (append_failed) {
        s.reset.store(true, .release);
        s.rx_cond.broadcast(conn.io);
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        rstStreamCode(conn, fh.sid, .internal_error);
        return true;
    }
    if (end_stream) s.rx_eof = true;
    // Padding/framing overhead is "consumed" on arrival: credit it immediately.
    const overhead: i64 = fc_len - @as(i64, @intCast(data.len));
    const d = if (overhead > 0) s.creditStreamLocked(overhead) else 0;
    s.rx_cond.broadcast(conn.io);
    s.rx_mu.unlock(conn.io);
    conn.streams_mu.unlock(conn.io);
    if (d > 0) sendWindowUpdate(conn, fh.sid, d);
    return true;
```

3g. `handleHeaders`:在流创建的 struct literal 里,`.send_window = conn.peer.initial_window_size,` 一行之后加:

```zig
        .recv_window = @intCast(conn.srv.config.initial_window_size),
```

3h. 删除 `max_request_body` 常量及其 doc 注释(现无引用)。

3i. 加 RED 用例 A(与实现一起加:该用例编码的"越窗 RST"在旧代码不存在,旧代码会缓存不 RST,`readFrameOfType(.rst_stream)` 将**阻塞挂起** —— 这就是"缺失"的表现,故不单独跑 red,直接随实现验证 green):

```zig
test "h2: inbound stream flow control resets on window overflow" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = flowEchoHandler,
        .config = .{ .initial_window_size = 100 }, // tiny window
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameOfType(testing.allocator, &reader.interface, .settings);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);
    // 200 bytes > 100-byte advertised window → FLOW_CONTROL_ERROR on the stream.
    var payload: [200]u8 = @splat('y');
    try writeFrame(&writer.interface, .data, 0, 1, &payload);

    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.flow_control_error)), std.mem.readInt(u32, rst.payload[0..4], .big));
}
```

- [ ] **Step 4: 跑全套测试**

Run: `zig build test --summary all`
Expected: PASS —— 现有全部 + B/C + A 全绿(47/47)。若 A 挂起,说明越窗 `RST` 没生效,检查 3f。

- [ ] **Step 5: Commit**

```bash
git add src/server.zig
git commit -m "server: per-stream inbound flow control — credit on consume, reset on overflow"
```

---

### Task 2: connection 级入站流控 + 启动放大 + 越窗 GOAWAY + 无泄漏返还

**Files:**
- Modify: `src/server.zig`
  - `Config`:加 `connection_window_size`
  - `Connection`:加 `recv_mu`/`conn_recv_window`/`conn_recv_pending`
  - 加 `clampConnWindow` + `creditConn` helper
  - `serveConn`:启动放大连接窗
  - `handleData`:连接扣减 + 越窗 `GOAWAY`;所有丢弃路径返还连接窗;padding 连接补
  - `streamRead`:消费时同时补连接窗
  - `runStream` 清理 defer:流终止时返还未消费残留的连接窗
  - **修** 既有测试 "http2 raw frame round trip"(启动新增 stream-0 `WINDOW_UPDATE` 会打乱其定位读)
- Test: 新增连接越窗 + 无泄漏用例

**Interfaces (Consumes/Produces):**
- Consumes(Task 1):`sendWindowUpdate`、`H2Stream.creditStreamLocked`、`recv_window`。
- Produces:
  - `Config.connection_window_size: u32`
  - `Connection.recv_mu`/`conn_recv_window: i64`/`conn_recv_pending: i64`
  - `fn clampConnWindow(v: u32) i64`
  - `fn creditConn(conn: *Connection, amt: i64) i64` —— 自取 `recv_mu`;累加到 `conn_recv_pending`,越过 `clampConnWindow(cfg.connection_window_size)/2` 阈值则并入 `conn_recv_window`、返回待发增量(否则 0)。**调用方须在锁外用返回值发 stream-0 `WINDOW_UPDATE`。**

- [ ] **Step 1: 写连接级用例(D 越窗、E 无泄漏)**

```zig
/// Sleeps without reading the request body, then responds — leaves the body
/// unconsumed so connection-level accounting is exercised.
fn sleepNoReadHandler(ctx: *types.Context) anyerror!void {
    Io.sleep(ctx.io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .awake) catch {};
    try ctx.res.send(200, "text/plain", "ok");
}

/// Ignores the request body entirely and responds immediately.
fn ignoreBodyHandler(ctx: *types.Context) anyerror!void {
    try ctx.res.send(200, "text/plain", "ok");
}

test "h2: inbound connection flow control GOAWAYs on window overflow" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = sleepNoReadHandler,
        // Large per-stream window so the STREAM window can't trip first;
        // connection window stays at the RFC floor 65535 (no startup enlarge).
        .config = .{ .initial_window_size = 1 << 20, .connection_window_size = 65535 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [65600]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameOfType(testing.allocator, &reader.interface, .settings);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);
    // Send 65536 bytes (> 65535 conn window) in 16384-byte frames; handler never
    // reads, so no credit comes back → connection window goes negative.
    var chunk: [16384]u8 = @splat('z');
    var sent: usize = 0;
    while (sent < 65536) : (sent += chunk.len) try writeFrame(&writer.interface, .data, 0, 1, &chunk);

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.flow_control_error)), std.mem.readInt(u32, goaway.payload[4..8], .big));
}

test "h2: connection window is returned when a handler skips the body (no leak)" {
    const client_mod = @import("client.zig");
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = ignoreBodyHandler, // never reads the body
        // Small connection window so a leak would exhaust it within a few streams.
        .config = .{ .connection_window_size = 65535 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    var client: client_mod.Client = undefined;
    try client.init(testing.io, testing.allocator, &reader.interface, &writer.interface);
    defer client.deinit();

    var body: [32 * 1024]u8 = @splat('b');
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // 10 streams × 32 KiB = 320 KiB total, far beyond the 65535 conn window.
    // Without teardown/discard credit the client's connection send window would
    // be exhausted after ~2 streams and this would hang. It must not.
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const s = try client.openStream(.{ .path = "/x", .method = "POST" }, false);
        try s.send(&body, true);
        while (true) {
            switch (try s.readEvent(arena_state.allocator())) {
                .data => |d| if (d.end_stream) break,
                .headers => |h| if (h.end_stream) break,
                .rst, .goaway => return error.UnexpectedStreamEnd,
            }
        }
        s.close();
    }
}
```

- [ ] **Step 2: 跑测试(观察当前状态)**

Run: `zig build test --summary all`
Expected: 编译通过(D/E 引用的都是现有 API + 将加的 `connection_window_size` —— 注意:此步在实现前,`connection_window_size` 字段尚不存在,故 **D/E 会编译失败**)。这是预期的 RED(字段缺失)。若想先看运行时 RED,可临时把 D/E 的 `.connection_window_size = …` 去掉跑一次:D 在旧代码(即刻补满、无连接跟踪)下永不 GOAWAY → 挂起;E 在旧代码下即刻补满连接窗 → 反而能过(旧代码无连接背压)。实现后二者随字段一起转绿。

- [ ] **Step 3: 实现 Task 2**

3a. `Config` 里 `initial_window_size` 字段之后加:

```zig
    /// Connection-level inbound flow-control window (aggregate across streams).
    /// RFC's fixed initial is 65535; if larger, we enlarge via a stream-0
    /// WINDOW_UPDATE at startup. Clamped to [65535, 2^31-1].
    connection_window_size: u32 = 1 << 20,
```

3b. `Connection` 里 `closing` 字段之前加:

```zig
    // Inbound (receive) flow control, connection-level. recv_mu (leaf lock).
    recv_mu: Io.Mutex = .init,
    conn_recv_window: i64 = 65535,
    conn_recv_pending: i64 = 0,
```

3c. 加 helper(放在 `sendWindowUpdate` 附近):

```zig
fn clampConnWindow(v: u32) i64 {
    return @intCast(@min(@max(v, 65535), 0x7fff_ffff));
}

/// Records `amt` connection-level consumed/returned bytes; returns the
/// stream-0 WINDOW_UPDATE increment to emit (0 if below threshold). Takes
/// recv_mu itself — caller must NOT hold it, and must emit the returned
/// increment via sendWindowUpdate(conn, 0, d) AFTER releasing any lock.
fn creditConn(conn: *Connection, amt: i64) i64 {
    conn.recv_mu.lockUncancelable(conn.io);
    defer conn.recv_mu.unlock(conn.io);
    conn.conn_recv_pending += amt;
    const threshold = @max(@as(i64, 1), clampConnWindow(conn.srv.config.connection_window_size) >> 1);
    if (conn.conn_recv_pending >= threshold) {
        const d = conn.conn_recv_pending;
        conn.conn_recv_window += d;
        conn.conn_recv_pending = 0;
        return d;
    }
    return 0;
}
```

3d. `serveConn`:把 `conn.sendOurSettings() catch return;` 之后改为:

```zig
    conn.sendOurSettings() catch return;
    {
        // Enlarge the connection-level receive window past the RFC 65535 floor.
        const cwnd = clampConnWindow(srv.config.connection_window_size);
        conn.conn_recv_window = cwnd;
        if (cwnd > 65535) sendWindowUpdate(&conn, 0, cwnd - 65535);
    }
    readLoop(&conn, r);
    conn.drainWorkers();
```

3e. `handleData`:把 Task 1 留下的即刻连接补窗块(注释 "Connection-level flow control still auto-replenishes here …")替换为连接扣减 + 越窗 `GOAWAY`:

```zig
    // Connection-level inbound flow control: deduct the full frame length.
    if (payload.len > 0) {
        const fc: i64 = @intCast(payload.len);
        conn.recv_mu.lockUncancelable(conn.io);
        conn.conn_recv_window -= fc;
        const overflow = conn.conn_recv_window < 0;
        conn.recv_mu.unlock(conn.io);
        if (overflow) {
            sendGoaway(conn, .flow_control_error);
            return false;
        }
    }
```

3f. `handleData` 投递段:各丢弃路径 + padding 加连接返还/补。具体:
- **stream 不存在**分支(`orelse { conn.streams_mu.unlock(conn.io); return true; }`)改为:

```zig
    const s = conn.streams.get(fh.sid) orelse {
        conn.streams_mu.unlock(conn.io);
        // Frame won't reach any handler: return its connection-level credit.
        if (payload.len > 0) {
            const d = creditConn(conn, @intCast(payload.len));
            if (d > 0) sendWindowUpdate(conn, 0, d);
        }
        return true;
    };
```

- **流窗越界 RST** 分支:在 `rstStreamCode(conn, fh.sid, .flow_control_error);` 之前加连接返还(整帧不入缓冲):

```zig
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        {
            const dc = creditConn(conn, fc_len);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
        rstStreamCode(conn, fh.sid, .flow_control_error);
        return true;
```
（`append_failed` 的 `internal_error` 分支同样在 `rstStreamCode` 前加相同的 `creditConn(conn, fc_len)` + 发送。）

- **padding 开销**:把 Task 1 的 `const d = if (overhead > 0) s.creditStreamLocked(overhead) else 0;` 之后、发送前,追加连接级补:

```zig
    const d = if (overhead > 0) s.creditStreamLocked(overhead) else 0;
    s.rx_cond.broadcast(conn.io);
    s.rx_mu.unlock(conn.io);
    conn.streams_mu.unlock(conn.io);
    const dc = if (overhead > 0) creditConn(conn, overhead) else 0;
    if (d > 0) sendWindowUpdate(conn, fh.sid, d);
    if (dc > 0) sendWindowUpdate(conn, 0, dc);
    return true;
```

3g. `streamRead`:消费时补连接窗。把 Task 1 的:

```zig
                const d = self.creditStreamLocked(@intCast(n));
                self.rx_mu.unlock(conn.io);
                if (d > 0) sendWindowUpdate(conn, self.id, d);
                return n;
```
改为:

```zig
                const d = self.creditStreamLocked(@intCast(n));
                self.rx_mu.unlock(conn.io);
                const dc = creditConn(conn, @intCast(n));
                if (d > 0) sendWindowUpdate(conn, self.id, d);
                if (dc > 0) sendWindowUpdate(conn, 0, dc);
                return n;
```
(注意锁序:`creditConn` 取 `recv_mu` 在 `rx_mu` **释放之后**调用 —— 无嵌套,更安全;与 spec 的 `rx_mu → recv_mu` 不冲突,因为这里根本不同时持有两锁。)

3h. `runStream` 清理 defer:在 `removeStream(conn, st.id);` 之后、`st.rx_buf.deinit(conn.gpa);` 之前加:

```zig
        removeStream(conn, st.id);
        // Return connection-level credit for body bytes the handler never
        // consumed (e.g. it returned without draining the request body).
        // After removeStream the stream is unreachable by the reader thread,
        // so rx_buf/rx_off are stable here without rx_mu.
        const leftover: i64 = @intCast(st.rx_buf.items.len - st.rx_off);
        if (leftover > 0) {
            const dc = creditConn(conn, leftover);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
        st.rx_buf.deinit(conn.gpa);
```

3i. **修既有测试** "http2 raw frame round trip":它用默认 config(`connection_window_size` 默认 1 MiB → 启动发 stream-0 `WINDOW_UPDATE`),其读取 settings-ack 的一行是定位 `readFrameAlloc`,会先读到那个 `WINDOW_UPDATE`。把:

```zig
    var ack = try readFrameAlloc(testing.allocator, &reader.interface);
    defer ack.deinit(testing.allocator);
    try testing.expectEqual(FrameType.settings, ack.header.ftype);
    try testing.expectEqual(flag_ack, ack.header.flags);
```
改为(用 `readFrameOfType(.settings)` 跳过启动 `WINDOW_UPDATE`,拿到 settings-ack):

```zig
    var ack = try readFrameOfType(testing.allocator, &reader.interface, .settings);
    defer ack.deinit(testing.allocator);
    try testing.expectEqual(flag_ack, ack.header.flags);
```

- [ ] **Step 4: 跑全套测试**

Run: `zig build test --summary all`
Expected: PASS —— 现有全部(含 3i 修好的 round-trip)+ Task 1 的 A/B/C + Task 2 的 D/E 全绿(49/49)。若某历史用例因启动 `WINDOW_UPDATE` 定位读错位而失败,用同法改成 `readFrameOfType(...)` 跳过(审计显示仅 round-trip 一处;运行确认)。

- [ ] **Step 5: Commit**

```bash
git add src/server.zig
git commit -m "server: connection-level inbound flow control with leak-free credit return"
```

---

## Self-Review

**Spec coverage:**
- per-stream 扣减/消费补窗/阈值批量/越窗 RST/移除 8MB → Task 1(3a–3h)✓
- connection 扣减/越窗 GOAWAY/启动放大/config → Task 2(3a–3g)✓
- 连接窗返还总不变式(消费 / 流终止残留 / 三条丢弃路径)→ Task 2(3f stream-不存在 + 越窗 RST + OOM;3h 流终止残留;3g 消费)✓
- 锁序 `recv_mu` 叶子、锁外写帧 → `creditConn` 自取自放、返回值锁外发送;`streamRead`/teardown 在释放 `rx_mu` 后调 `creditConn` ✓
- 测试 1/2/3/4/5 → B(e2e 背压)/A(stream 越窗)/C(stream WU on consume)/D(conn 越窗)/E(无泄漏)+ 3i 回归 ✓

**Placeholder scan:** 无 TBD;每步给出可粘贴代码与整段替换目标。

**Type consistency:**
- `sendWindowUpdate(conn, sid, incr: i64)`、`creditStreamLocked(amt: i64) i64`、`creditConn(conn, amt: i64) i64`、`clampConnWindow(v: u32) i64` 在 Task 1/2 定义并被一致引用。
- `recv_window`/`recv_pending`(H2Stream)、`conn_recv_window`/`conn_recv_pending`/`recv_mu`(Connection)、`Config.connection_window_size` 命名一致。
- `fc_len`/`overhead` 在 `handleData` 内定义并被 3e/3f 一致使用(注意 `fc_len` 在投递段定义,3f 的 RST 返还引用它,处于同一作用域)。
