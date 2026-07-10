# 接受请求 trailers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 服务端把已开流上的第二个 HEADERS 当作请求 trailers 处理(置 body-EOF、丢字段),而不是把整条连接 GOAWAY 掉;已关闭/idle 流上的 HEADERS 软化为 RST_STREAM。

**Architecture:** `handleHeaders` 组装完整 header block 后按 `fh.sid` 分类:已开流 → `handleTrailingHeaders`(临时 arena 解码保 HPACK 同步、校验 trailers、置 EOF 或以流错误终止 worker);偶数 id → GOAWAY;奇数且 ≤ last 且不在 map → 解码保同步后 RST_STREAM(STREAM_CLOSED);新奇数 id → 原新流逻辑。

**Tech Stack:** Zig 0.16.0,`std.Io`,无第三方依赖。

**Spec:** `docs/superpowers/specs/2026-07-10-request-trailers-design.md`

## Global Constraints

- Zig 0.16.0;仅用 `std`;非测试改动限于 `src/server.zig` 与 `src/proto.zig`。
- 传输层无关;测试用现有 socketpair 脚手架(`newSocketPair`/`serveRawH2OnFd`/`peerStream`/`readFrameAlloc`/`readFrameOfType`/`writeFrame`/`findHeaderValue`)+ `hpack.Encoder.encodeTrailers` 造 trailer 块;无真实网络。
- **保留连接却带 header block 的路径(trailing / closed)必须 HPACK 解码**(到临时 arena,绝不用 worker 持有的 `st.arena()`),否则解码器失步 → 后续 header 全崩;解码失败一律 `GOAWAY(protocol_error)`。
- **对仍在 map 的活流发 RST**(无 END_STREAM / 含伪首部 / 已结束)必须与 `resetStream` 语义一致:置 `reset` + `rx_cond.broadcast` + `wakeSenders()`,以终止阻塞在 `sendBody`/`streamRead` 的本地 worker;仅"锁下重取已不在 map"那路纯回 STREAM_CLOSED。
- 锁序 `streams_mu → rx_mu`;`wakeSenders()`/写帧在释放 `rx_mu`/`streams_mu` 之后。
- 每个任务结束跑 `zig build test --summary all` 全绿(现状 49/49 + 新增用例);伪 "failed command … --listen=-" 行忽略,以 "Build Summary: N/N tests passed" 为准。

---

### Task 1: HEADERS 流 id 分类 + 请求 trailers 接受 + 已关闭流软化

**Files:**
- Modify: `src/proto.zig`(`ErrorCode` 加 `stream_closed = 0x5`)
- Modify: `src/server.zig`(`handleHeaders` 分类;新增 `decodeDiscard` + `handleTrailingHeaders`)
- Test: `src/server.zig` `test` 区(4 个用例)

**Interfaces (Produces):**
- `proto.ErrorCode.stream_closed`(= `ErrorCode.stream_closed`,已在 server.zig 别名导入 `ErrorCode`)
- `fn decodeDiscard(conn: *Connection, block: []const u8) !void`
- `fn handleTrailingHeaders(conn: *Connection, fh: ParsedHeader, block: []const u8) !void`

- [ ] **Step 1: 写 4 个用例(测试先行)**

在 `test` 区末尾追加(`flowEchoHandler` 与 `h2TestHandler` 已存在于该文件;`hpack`/`ErrorCode`/`our_header_table_size`/`findHeaderValue`/`preface` 均在作用域内):

```zig
// Canonical request block: :method GET, :scheme http, :path /, :authority www.example.com
const trailers_req_block = [_]u8{
    0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
};

fn readFrameWith(alloc: std.mem.Allocator, r: *Io.Reader, want: FrameType, sid: u31) !TestFrame {
    while (true) {
        var f = try readFrameAlloc(alloc, r);
        if (f.header.ftype == want and f.header.sid == sid) return f;
        f.deinit(alloc);
    }
}

test "h2: request trailers are accepted; connection survives for later streams" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = flowEchoHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameOfType(testing.allocator, &reader.interface, .settings);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Stream 1: HEADERS (no END_STREAM) + DATA + trailing HEADERS (END_STREAM + a field).
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    try writeFrame(&writer.interface, .data, 0, 1, "body");
    var tblock: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeTrailers(arena, &tblock, &[_]hpack.Header{.{ .name = "x-sum", .value = "1" }});
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, tblock.items);

    // Stream 3: a later, independent bodyless request. On the pre-fix code the
    // trailing HEADERS above GOAWAYs the connection, so stream 3 never gets a
    // response and the read below hits EOF. On the fixed code the connection
    // survives and stream 3 is answered.
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, &trailers_req_block);

    var resp3 = try readFrameWith(testing.allocator, &reader.interface, .headers, 3);
    defer resp3.deinit(testing.allocator);
    var dec = hpack.Decoder.init(testing.allocator, our_header_table_size);
    defer dec.deinit();
    const hs = try dec.decode(arena, resp3.payload);
    try testing.expectEqualStrings("200", findHeaderValue(hs, ":status").?);
}

test "h2: trailing HEADERS without END_STREAM resets the stream (protocol_error)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = flowEchoHandler, .config = .{} };
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

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    try writeFrame(&writer.interface, .data, 0, 1, "body");
    var tblock: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeTrailers(arena_state.allocator(), &tblock, &[_]hpack.Header{.{ .name = "x-sum", .value = "1" }});
    // Second HEADERS WITHOUT END_STREAM → not valid trailers.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, tblock.items);

    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), std.mem.readInt(u32, rst.payload[0..4], .big));
}

test "h2: trailers containing a pseudo-header reset the stream (protocol_error)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = flowEchoHandler, .config = .{} };
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

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    try writeFrame(&writer.interface, .data, 0, 1, "body");
    // Trailers must not contain pseudo-headers; include ":method" to violate that.
    var tblock: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeTrailers(arena_state.allocator(), &tblock, &[_]hpack.Header{.{ .name = ":method", .value = "GET" }});
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, tblock.items);

    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), std.mem.readInt(u32, rst.payload[0..4], .big));
}

test "h2: HEADERS on a closed stream is RST(STREAM_CLOSED), not GOAWAY" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = h2TestHandler, .config = .{} };
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

    // Stream 1: complete a bodyless request and drain its response to END_STREAM,
    // so the handler has finished (stream closing/closed).
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
    while (true) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        const es = f.header.flags & flag_end_stream != 0 and (f.header.ftype == .data or f.header.ftype == .headers);
        f.deinit(testing.allocator);
        if (es) break;
    }
    // A fresh HEADERS on the now-closed stream 1: RST(STREAM_CLOSED), connection alive.
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.stream_closed)), std.mem.readInt(u32, rst.payload[0..4], .big));
}
```

- [ ] **Step 2: 跑测试确认 RED**

Run: `zig build test --summary all`
Expected: FAIL —— 4 个新用例都失败。旧代码对第二个/已关闭流的 HEADERS 一律 `GOAWAY(protocol_error)` 并关连接,于是:test 1 读 stream-3 响应时遇 EOF;test 2/3/4 等 `RST_STREAM` 却因 GOAWAY 后连接关闭而遇 EOF(`error.EndOfStream`)。均以 error 失败(非挂起,因 GOAWAY 后 readLoop 退出、`serveConn` 返回、线程可 join)。若某个不是这样失败,先核对测试。

- [ ] **Step 3: 实现**

3a. `src/proto.zig` 的 `ErrorCode` 枚举里,在 `flow_control_error = 0x3,` 之后加一行:

```zig
    stream_closed = 0x5,
```

3b. `src/server.zig`:把 `handleHeaders` 里下面这段(现 "New stream id must be odd and strictly increasing." 起到 `conn.last_stream_id = fh.sid;`):

```zig
    // New stream id must be odd and strictly increasing.
    if (fh.sid <= conn.last_stream_id or fh.sid % 2 == 0) {
        sendGoaway(conn, .protocol_error);
        return error.ProtocolError;
    }
    conn.last_stream_id = fh.sid;
```

整段替换为:

```zig
    // Classify this HEADERS by stream id. An id that is already open means this is
    // a second HEADERS on that stream — request trailers (RFC 7540 §8.1) — not a
    // new stream. Used only for routing; handleTrailingHeaders re-checks under
    // streams_mu because the worker may remove the stream in the meantime.
    conn.streams_mu.lockUncancelable(conn.io);
    const already_open = conn.streams.contains(fh.sid);
    conn.streams_mu.unlock(conn.io);
    if (already_open) return handleTrailingHeaders(conn, fh, block.items);

    // Client-initiated streams use odd ids.
    if (fh.sid % 2 == 0) {
        sendGoaway(conn, .protocol_error);
        return error.ProtocolError;
    }
    // An odd id at or below the highest we've opened but not currently open is a
    // closed (or idle) stream. Decode the block to keep the HPACK decoder synced
    // (we keep the connection alive), then RST rather than GOAWAY.
    if (fh.sid <= conn.last_stream_id) {
        decodeDiscard(conn, block.items) catch {
            sendGoaway(conn, .protocol_error);
            return error.ProtocolError;
        };
        rstStreamCode(conn, fh.sid, .stream_closed);
        return;
    }
    conn.last_stream_id = fh.sid;
```

3c. `src/server.zig`:在 `handleHeaders` 之后(或 helper 区)新增两个函数:

```zig
/// Decodes a header block into a throwaway arena purely to advance the HPACK
/// dynamic table (keeping the decoder in sync), discarding the result. Used on
/// paths that keep the connection alive but do not deliver the headers.
fn decodeDiscard(conn: *Connection, block: []const u8) !void {
    var tmp = std.heap.ArenaAllocator.init(conn.gpa);
    defer tmp.deinit();
    _ = try conn.decoder.decode(tmp.allocator(), block);
}

/// Handles a second HEADERS frame on an already-open stream: HTTP/2 request
/// trailers (RFC 7540 §8.1). The block is HPACK-decoded on this (reader) thread
/// into a throwaway arena — never st.arena(), which the worker owns concurrently.
/// Valid trailers (END_STREAM set, no pseudo-headers) end the request body; any
/// other case is a stream error that also tears down the local worker.
fn handleTrailingHeaders(conn: *Connection, fh: ParsedHeader, block: []const u8) !void {
    var tmp = std.heap.ArenaAllocator.init(conn.gpa);
    defer tmp.deinit();
    const decoded = conn.decoder.decode(tmp.allocator(), block) catch {
        sendGoaway(conn, .protocol_error); // HPACK failure is connection-fatal
        return error.ProtocolError;
    };

    // Trailers must carry END_STREAM and must not contain pseudo-headers.
    var invalid_code: ?ErrorCode = null;
    if (fh.flags & flag_end_stream == 0) {
        invalid_code = .protocol_error;
    } else for (decoded) |h| {
        if (h.name.len > 0 and h.name[0] == ':') {
            invalid_code = .protocol_error;
            break;
        }
    }

    conn.streams_mu.lockUncancelable(conn.io);
    const s = conn.streams.get(fh.sid) orelse {
        conn.streams_mu.unlock(conn.io);
        rstStreamCode(conn, fh.sid, .stream_closed); // worker already finished/removed
        return;
    };
    s.rx_mu.lockUncancelable(conn.io);
    // Already half-closed (END_STREAM seen) → HEADERS after end is STREAM_CLOSED;
    // otherwise bad trailers → invalid_code. Either way it's a stream error that
    // must also terminate the local worker.
    const rst_code: ?ErrorCode = if (s.rx_eof) .stream_closed else invalid_code;
    if (rst_code) |code| {
        s.reset.store(true, .release);
        s.rx_cond.broadcast(conn.io);
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        conn.wakeSenders(); // rx_cond can't wake a worker blocked on the send window
        rstStreamCode(conn, fh.sid, code);
        return;
    }
    // Valid trailers: end the request body; drop the fields.
    s.rx_eof = true;
    s.rx_cond.broadcast(conn.io);
    s.rx_mu.unlock(conn.io);
    conn.streams_mu.unlock(conn.io);
}
```

- [ ] **Step 4: 跑全套测试**

Run: `zig build test --summary all`
Expected: PASS —— 现有 49 + 4 新用例 = 53/53。若 test 3 未得到 RST,检查 `encodeTrailers` 是否确实把 `:method` 作为字面名发出(它按名查静态表 index 2 并以字面 name-index 发出,解码回 `:method`,分类为伪首部)。

- [ ] **Step 5: Commit**

```bash
git add src/proto.zig src/server.zig
git commit -m "server: accept request trailers; RST closed-stream HEADERS instead of GOAWAY"
```

---

## Self-Review

**Spec coverage:**
- `stream_closed = 0x5` → 3a ✓
- 七类分类(已开流→trailers;偶数→GOAWAY;奇数≤last→RST stream_closed;新奇数→新流)→ 3b ✓
- `handleTrailingHeaders`:临时 arena 解码 + END_STREAM/伪首部校验 + 已结束→STREAM_CLOSED + 活流 RST 置 reset+唤醒两侧(`wakeSenders`)+ 合法→置 rx_eof + 重取已移除→纯 STREAM_CLOSED → 3c ✓
- `decodeDiscard` 保 closed 路径 HPACK 同步 → 3b/3c ✓
- 测试 1(连接存活/trailers 接受)/2(无 ES→RST)/3(伪首部→RST)/4(已关闭→RST stream_closed)+ 回归 → Step 1/4 ✓

**Placeholder scan:** 无 TBD;每步完整可粘贴代码。

**Type consistency:**
- `ErrorCode.stream_closed` 在 proto.zig 定义、server.zig 经 `const ErrorCode = proto2.ErrorCode;` 别名引用一致。
- `decodeDiscard(conn, block) !void`、`handleTrailingHeaders(conn, fh, block) !void`、`rstStreamCode(conn, sid, code)`、`conn.wakeSenders()`、`conn.decoder.decode(alloc, block)`、`s.rx_eof`/`s.reset`/`s.rx_cond`/`s.rx_mu` 均与现有定义一致。
- `handleTrailingHeaders` 返回 `!void`,经 `handleHeaders` 的 `return handleTrailingHeaders(...)` 传播到 readLoop 的 `handleHeaders(...) catch return`(GOAWAY 已在返回错误前发出)。
