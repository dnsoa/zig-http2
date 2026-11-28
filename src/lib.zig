//! zig-http2 — a dependency-free HTTP/2 (RFC 9113) server and client for Zig
//! 0.17's `std.Io` model. Transport-agnostic: callers supply any
//! `*std.Io.Reader`/`*std.Io.Writer` pair (e.g. a TLS-wrapped socket).
//!
//! Quick start:
//!   ```zig
//!   const h2 = @import("zig_http2");
//!
//!   // Server: fill a `h2.Server` and call `h2.serveConn` per connection.
//!   fn handler(ctx: *h2.Context) anyerror!void {
//!       try ctx.res.send(200, "text/plain", "hello");
//!   }
//!   var srv: h2.Server = .{ .io = io, .gpa = gpa, .handler = handler };
//!   h2.serveConn(&srv, &reader, &writer, null, "https");
//!
//!   // Client: wrap a transport, open a stream, send + read.
//!   var c: h2.Client = undefined;
//!   try c.init(io, gpa, &reader, &writer);
//!   defer c.deinit();
//!   const s = try c.openStream(.{ .path = "/svc/Echo" }, false);
//!   defer s.close();
//!   try s.send("ping", true);
//!   // s.readEvent(arena) yields .headers / .data / .rst / .goaway
//!   ```
//!
//! gRPC readiness: trailers, streaming request bodies (`ctx.body_reader`), and
//! bidirectional streaming (separate send/receive threads) are supported — the
//! shapes a gRPC server/client needs. Client limits: no PUSH_PROMISE (we
//! advertise ENABLE_PUSH=0 and tear down on a push), no PRIORITY, and `close()`
//! must be called per stream to reclaim it before `deinit` (never after `deinit`
//! has begun — cancel and join worker threads holding `*Stream` handles first).

const types = @import("types.zig");
pub const proto = @import("proto.zig");
pub const hpack = @import("hpack.zig");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");

// Top-level convenience re-exports.
pub const Header = types.Header;
pub const StreamPriority = types.StreamPriority;
pub const Request = types.Request;
pub const Response = types.Response;
pub const Sink = types.Sink;
pub const Context = types.Context;
pub const BodyReader = types.BodyReader;
pub const Handler = types.Handler;

pub const Server = server_mod.Server;
pub const Config = server_mod.Config;
pub const serveConn = server_mod.serveConn;

pub const Client = client_mod.Client;
pub const ClientConfig = client_mod.Config;
pub const Stream = client_mod.Stream;
pub const RequestHead = client_mod.RequestHead;
pub const Event = client_mod.Event;

pub const ErrorCode = proto.ErrorCode;

test {
    // Reference every internal module so its `test` blocks run from this root.
    _ = types;
    _ = proto;
    _ = hpack;
    _ = server_mod;
    _ = client_mod;
}

test "Stream re-export names the client stream type" {
    // External consumers store a `*h2.Stream` in their own structs (a field
    // needs a namable type, unlike the type-inferred doc example), so the
    // re-export must be exactly the type openStream hands out.
    if (Stream != client_mod.Stream) @compileError("h2.Stream must be the client stream type");
}

test "client close() after early server response does not trip rapid-reset limit (#23)" {
    const std = @import("std");
    const testing = std.testing;
    const Helper = struct {
        fn serve(srv: *Server, fd: std.posix.fd_t) void {
            defer _ = std.c.close(fd);
            const s: std.Io.net.Stream = .{ .socket = .{
                .handle = fd,
                .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
            } };
            var rbuf: [4096]u8 = undefined;
            var wbuf: [4096]u8 = undefined;
            var sr = s.reader(srv.io, &rbuf);
            var sw = s.writer(srv.io, &wbuf);
            serveConn(srv, &sr.interface, &sw.interface, null, "https");
        }
        fn earlyOk(ctx: *Context) anyerror!void {
            try ctx.res.send(200, "text/plain", "ok");
        }
    };

    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = std.c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = Helper.earlyOk,
        .config = .{ .idle_timeout_ms = 10_000 },
    };
    const th = try std.Thread.spawn(.{}, Helper.serve, .{ &srv, fds[0] });
    defer th.join();
    defer _ = std.c.close(fds[1]);

    const peer: std.Io.net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = peer.reader(testing.io, &rbuf);
    var sw = peer.writer(testing.io, &wbuf);

    var client: Client = undefined;
    try client.init(testing.io, testing.allocator, &sr.interface, &sw.interface);
    defer client.deinit();

    // 200 sequential streams where client never half-closes (end_stream=false),
    // server responds early without reading body, and client closes each stream
    // (emitting RST_STREAM(CANCEL)). Must complete 200/200 without ENHANCE_YOUR_CALM.
    for (0..200) |_| {
        const s = try client.openStream(.{ .path = "/early" }, false);
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        while (true) {
            const ev = s.readEvent(arena_state.allocator()) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            try testing.expect(ev != .rst and ev != .goaway);
        }
        s.close();
    }
    try testing.expect(client.goAway() == null);
    try testing.expect(!client.dead.load(.acquire));
}

test "Client.openStreamWithBody echoes unary and multi-frame bodies with Server (#44)" {
    const std = @import("std");
    const testing = std.testing;
    const Helper = struct {
        fn serve(srv: *Server, fd: std.posix.fd_t) void {
            defer _ = std.c.close(fd);
            const s: std.Io.net.Stream = .{ .socket = .{
                .handle = fd,
                .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
            } };
            var rbuf: [8192]u8 = undefined;
            var wbuf: [8192]u8 = undefined;
            var sr = s.reader(srv.io, &rbuf);
            var sw = s.writer(srv.io, &wbuf);
            serveConn(srv, &sr.interface, &sw.interface, null, "https");
        }
        fn echo(ctx: *Context) anyerror!void {
            var buf: std.ArrayList(u8) = .empty;
            if (ctx.body_reader) |br| {
                var tmp: [4096]u8 = undefined;
                while (true) {
                    const n = try br.read(&tmp);
                    if (n == 0) break;
                    try buf.appendSlice(ctx.arena, tmp[0..n]);
                }
            }
            try ctx.res.send(200, "application/octet-stream", buf.items);
        }
    };

    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = std.c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = Helper.echo,
        .config = .{ .idle_timeout_ms = 10_000 },
    };
    const th = try std.Thread.spawn(.{}, Helper.serve, .{ &srv, fds[0] });
    defer th.join();
    defer _ = std.c.close(fds[1]);

    const peer: std.Io.net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var sr = peer.reader(testing.io, &rbuf);
    var sw = peer.writer(testing.io, &wbuf);

    var client: Client = undefined;
    try client.init(testing.io, testing.allocator, &sr.interface, &sw.interface);
    defer client.deinit();

    // 1. Unary small body.
    {
        const s = try client.openStreamWithBody(.{ .method = "POST", .path = "/unary" }, "hello coalesced", true);
        defer s.close();
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(testing.allocator);
        while (true) {
            const ev = s.readEvent(arena_state.allocator()) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            switch (ev) {
                .data => |d| {
                    try got.appendSlice(testing.allocator, d.payload);
                    if (d.end_stream) break;
                },
                .headers => |h| if (h.end_stream) break,
                .rst, .goaway => return error.UnexpectedStreamEnd,
            }
        }
        try testing.expectEqualStrings("hello coalesced", got.items);
    }

    // 2. Multi-frame body (40000 B > 16384 B frame limit).
    {
        const big = try testing.allocator.alloc(u8, 40_000);
        defer testing.allocator.free(big);
        for (big, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);

        const s = try client.openStreamWithBody(.{ .method = "POST", .path = "/big" }, big, true);
        defer s.close();
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(testing.allocator);
        while (true) {
            const ev = s.readEvent(arena_state.allocator()) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            switch (ev) {
                .data => |d| {
                    try got.appendSlice(testing.allocator, d.payload);
                    if (d.end_stream) break;
                },
                .headers => |h| if (h.end_stream) break,
                .rst, .goaway => return error.UnexpectedStreamEnd,
            }
        }
        try testing.expectEqualSlices(u8, big, got.items);
    }
}

test "CDN streaming round trip: large response batches with custom max_frame_size and zero-alloc Stream.readBody" {
    const std = @import("std");
    const testing = std.testing;
    const payload_size: usize = 150_000;
    const Helper = struct {
        fn serve(srv: *Server, fd: std.posix.fd_t) void {
            defer _ = std.c.close(fd);
            const s: std.Io.net.Stream = .{ .socket = .{
                .handle = fd,
                .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
            } };
            var rbuf: [16384]u8 = undefined;
            var wbuf: [65536]u8 = undefined;
            var sr = s.reader(srv.io, &rbuf);
            var sw = s.writer(srv.io, &wbuf);
            serveConn(srv, &sr.interface, &sw.interface, null, "https");
        }
        fn originHandler(ctx: *Context) anyerror!void {
            ctx.res.status(200);
            try ctx.res.header("content-type", "application/octet-stream");
            ctx.res.setContentLength(payload_size);
            var chunk: [50_000]u8 = undefined;
            for (0..3) |part| {
                for (&chunk, 0..) |*b, idx| b.* = @truncate((part * 50_000 + idx) *% 13 +% 5);
                try ctx.res.write(&chunk);
            }
            try ctx.res.finish();
        }
    };

    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = std.c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = Helper.originHandler,
        .config = .{ .idle_timeout_ms = 10_000, .max_frame_size = 32768 },
    };
    const th = try std.Thread.spawn(.{}, Helper.serve, .{ &srv, fds[0] });
    defer th.join();
    defer _ = std.c.close(fds[1]);

    const peer: std.Io.net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [32768]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = peer.reader(testing.io, &rbuf);
    var sw = peer.writer(testing.io, &wbuf);

    var client: Client = undefined;
    try client.initWithConfig(testing.io, testing.allocator, &sr.interface, &sw.interface, .{
        .connection_window_size = 512 * 1024,
        .initial_window_size = 512 * 1024,
        .max_frame_size = 32768,
    });
    defer client.deinit();

    const s = try client.openStream(.{ .method = "GET", .path = "/asset.bin", .authority = "cdn.example.com" }, true);
    defer s.close();

    var hdr_buf: [512]u8 = undefined;
    var hdr_fba = std.heap.FixedBufferAllocator.init(&hdr_buf);
    const ev = try s.readEvent(hdr_fba.allocator());
    try testing.expect(ev == .headers);
    try testing.expect(!ev.headers.end_stream);

    var total: usize = 0;
    var buf: [16384]u8 = undefined;
    while (true) {
        const n = try s.readBody(&buf);
        if (n == 0) break;
        for (buf[0..n], 0..) |byte, idx| {
            const exp: u8 = @truncate((total + idx) *% 13 +% 5);
            try testing.expectEqual(exp, byte);
        }
        total += n;
    }
    try testing.expectEqual(payload_size, total);
}

test "CDN phase 2 end-to-end: stateful HPACK compression, static zero-copy, and concurrent multi-stream flow control" {
    const std = @import("std");
    const testing = std.testing;
    const Helper = struct {
        fn serve(srv: *Server, fd: std.posix.fd_t) void {
            defer _ = std.c.close(fd);
            const s: std.Io.net.Stream = .{ .socket = .{
                .handle = fd,
                .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
            } };
            var rbuf: [16384]u8 = undefined;
            var wbuf: [32768]u8 = undefined;
            var sr = s.reader(srv.io, &rbuf);
            var sw = s.writer(srv.io, &wbuf);
            serveConn(srv, &sr.interface, &sw.interface, "203.0.113.9", "https");
        }
        fn cdnEdge(ctx: *Context) anyerror!void {
            const pop = ctx.req.get("x-cdn-pop") orelse "none";
            const auth = ctx.req.get("authorization") orelse "missing";
            try ctx.res.header("server", "zig-cdn-edge/2.0");
            try ctx.res.header("cache-control", "public, max-age=31536000, immutable");
            try ctx.res.header("strict-transport-security", "max-age=63072000; includeSubDomains");
            try ctx.res.header("x-served-by", pop);
            try ctx.res.header("set-cookie", auth);
            try ctx.res.header("etag", ctx.req.path());
            if (std.mem.eql(u8, ctx.req.path(), "/stream")) {
                const body: [48_000]u8 = @splat('S');
                try ctx.res.send(200, "application/octet-stream", &body);
            } else {
                try ctx.res.send(200, "text/plain", ctx.req.path());
            }
        }
    };

    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = std.c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = Helper.cdnEdge,
        .config = .{ .idle_timeout_ms = 10_000, .max_encoder_table_size = 4096 },
    };
    const th = try std.Thread.spawn(.{}, Helper.serve, .{ &srv, fds[0] });
    defer th.join();
    defer _ = std.c.close(fds[1]);

    const peer: std.Io.net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = peer.reader(testing.io, &rbuf);
    var sw = peer.writer(testing.io, &wbuf);

    var client: Client = undefined;
    try client.initWithConfig(testing.io, testing.allocator, &sr.interface, &sw.interface, .{
        .connection_window_size = 256 * 1024,
        .initial_window_size = 32 * 1024,
        .max_encoder_table_size = 4096,
    });
    defer client.deinit();

    // 25 sequential hits exercising bidirectional dynamic HPACK compression + static zero-copy.
    var pbuf: [32]u8 = undefined;
    for (0..25) |i| {
        const req_path = std.fmt.bufPrint(&pbuf, "/hit/{d}", .{i}) catch unreachable;
        const s = try client.openStream(.{
            .method = "GET",
            .path = req_path,
            .authority = "cdn.example.com",
            .headers = &.{
                .{ .name = "x-cdn-pop", .value = "sin-01" },
                .{ .name = "user-agent", .value = "zig-cdn-probe/2.0" },
                .{ .name = "authorization", .value = "Bearer tok-xyz" },
            },
        }, true);
        defer s.close();

        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const ev = try s.readEvent(arena_state.allocator());
        try testing.expect(ev == .headers);
        // `:status: 200` is borrowed directly from `.rodata` StaticTable.
        try testing.expect(hpack.isStaticSlice(ev.headers.headers[0].name));
        try testing.expect(hpack.isStaticSlice(ev.headers.headers[0].value));

        var out_buf: [64]u8 = undefined;
        const n = try s.readBody(&out_buf);
        try testing.expectEqualStrings(req_path, out_buf[0..n]);
        try testing.expectEqual(@as(usize, 0), try s.readBody(&out_buf));
    }

    // Concurrent multi-stream downloads exercising lock-free `op_state` and per-stream `send_cond`.
    const Worker = struct {
        c: *Client,
        ok: bool = false,
        fn run(self: *@This()) void {
            const st = self.c.openStream(.{
                .method = "GET",
                .path = "/stream",
                .authority = "cdn.example.com",
                .headers = &.{
                    .{ .name = "x-cdn-pop", .value = "sin-01" },
                    .{ .name = "authorization", .value = "Bearer tok-xyz" },
                },
            }, true) catch return;
            defer st.close();

            var hdr_mem: [1024]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&hdr_mem);
            const ev = st.readEvent(fba.allocator()) catch return;
            if (ev != .headers) return;

            var got: usize = 0;
            var chunk: [8192]u8 = undefined;
            while (true) {
                const n = st.readBody(&chunk) catch return;
                if (n == 0) break;
                got += n;
            }
            self.ok = (got == 48_000);
        }
    };
    var workers: [4]Worker = @splat(.{ .c = &client });
    var threads: [4]std.Thread = undefined;
    for (&workers, 0..) |*w, idx| threads[idx] = try std.Thread.spawn(.{}, Worker.run, .{w});
    for (&threads) |t| t.join();
    for (&workers) |w| try testing.expect(w.ok);
}

test "Phase 3 end-to-end: 103 Early Hints, bidirectional Trailers, Extended CONNECT WebSocket, and PRIORITY_UPDATE" {
    const std = @import("std");
    const testing = std.testing;

    const EdgeHandler = struct {
        fn serve(srv: *Server, fd: std.posix.fd_t) void {
            defer _ = std.c.close(fd);
            const s: std.Io.net.Stream = .{ .socket = .{
                .handle = fd,
                .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
            } };
            var rbuf: [16384]u8 = undefined;
            var wbuf: [16384]u8 = undefined;
            var sr = s.reader(srv.io, &rbuf);
            var sw = s.writer(srv.io, &wbuf);
            serveConn(srv, &sr.interface, &sw.interface, "198.51.100.7", "https");
        }

        fn handle(ctx: *Context) anyerror!void {
            // 1. RFC 8441 Extended CONNECT full-duplex WebSocket tunnel.
            if (ctx.req.protocol) |proto_name| {
                try testing.expectEqualStrings("CONNECT", ctx.req.method);
                try testing.expectEqualStrings("websocket", proto_name);
                ctx.res.status(200);
                try ctx.res.header("sec-websocket-protocol", "chat.v1");
                try ctx.res.flushHead();

                const br = ctx.body_reader.?;
                var frame_buf: [64]u8 = undefined;
                while (true) {
                    const n = try br.read(&frame_buf);
                    if (n == 0) break;
                    try ctx.res.write("ws-echo:");
                    try ctx.res.write(frame_buf[0..n]);
                }
                return;
            }

            // 2. 103 Early Hints -> 200 OK response.
            if (std.mem.eql(u8, ctx.req.path(), "/early-hints")) {
                try ctx.res.sendEarlyHints(&.{
                    .{ .name = "link", .value = "</critical.css>; rel=preload; as=style" },
                    .{ .name = "link", .value = "</app.js>; rel=preload; as=script" },
                });
                try ctx.res.send(200, "text/html", "<html>ok</html>");
                return;
            }

            // 3. Bidirectional request & response trailers + RFC 9218 Priority inspection.
            if (std.mem.eql(u8, ctx.req.path(), "/upload-trailers")) {
                var body_bytes: std.ArrayList(u8) = .empty;
                if (ctx.body_reader) |br| {
                    var tmp: [256]u8 = undefined;
                    while (true) {
                        const n = try br.read(&tmp);
                        if (n == 0) break;
                        try body_bytes.appendSlice(ctx.arena, tmp[0..n]);
                    }
                }
                const req_sum = ctx.req.getTrailer("x-sha256") orelse "none";
                const ctx_tr = ctx.trailers();
                try testing.expectEqual(@as(usize, 2), ctx_tr.len);
                ctx.res.status(200);
                try ctx.res.header("x-seen-urgency", if (ctx.req.priority.urgency == 1 and ctx.req.priority.incremental) "1-inc" else "other");
                try ctx.res.write(body_bytes.items);
                try ctx.res.trailer("x-verified-sha256", req_sum);
                try ctx.res.trailer("grpc-status", "0");
                try ctx.res.finish();
                return;
            }

            try ctx.res.send(404, "text/plain", "not found");
        }
    };

    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = std.c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = EdgeHandler.handle,
        .config = .{
            .enable_connect_protocol = true,
            .enable_extensible_priorities = true,
            .max_header_list_size = 32 * 1024,
        },
    };
    const th = try std.Thread.spawn(.{}, EdgeHandler.serve, .{ &srv, fds[0] });
    defer th.join();
    defer _ = std.c.close(fds[1]);

    const peer: std.Io.net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = peer.reader(testing.io, &rbuf);
    var sw = peer.writer(testing.io, &wbuf);

    var client: Client = undefined;
    try client.initWithConfig(testing.io, testing.allocator, &sr.interface, &sw.interface, .{
        .max_header_list_size = 32 * 1024,
    });
    defer client.deinit();

    // Wait briefly until client processes server's initial SETTINGS (enabling Extended CONNECT).
    while (!client.peerSupportsExtendedConnect()) {
        std.Io.sleep(testing.io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
    }
    try testing.expect(client.peerDisablesRfc7540Priorities());

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Case A: 103 Early Hints followed by 200 OK.
    {
        const s = try client.tryOpenStream(.{
            .method = "GET",
            .path = "/early-hints",
            .authority = "edge.example.com",
        }, true);
        defer s.close();

        const ev103 = try s.readEvent(arena);
        try testing.expect(ev103 == .headers and !ev103.headers.end_stream);
        try testing.expectEqualStrings("103", ev103.headers.headers[0].value);

        const ev200 = try s.readEvent(arena);
        try testing.expect(ev200 == .headers and !ev200.headers.end_stream);
        try testing.expectEqualStrings("200", ev200.headers.headers[0].value);

        var html_buf: [64]u8 = undefined;
        const n = try s.readBody(&html_buf);
        try testing.expectEqualStrings("<html>ok</html>", html_buf[0..n]);
        try testing.expectEqual(@as(usize, 0), try s.readBody(&html_buf));
    }

    // Case B: Bidirectional request + response trailers + RFC 9218 Priority + setPriority.
    {
        const s = try client.tryOpenStream(.{
            .method = "POST",
            .path = "/upload-trailers",
            .authority = "edge.example.com",
            .priority = .{ .urgency = 1, .incremental = true },
            .headers = &.{.{ .name = "te", .value = "trailers" }},
        }, false);
        defer s.close();

        try s.setPriority(.{ .urgency = 0, .incremental = false });
        try s.send("chunk-1+", false);
        try s.send("chunk-2", false);
        try s.sendTrailers(&.{
            .{ .name = "x-sha256", .value = "deadbeef" },
            .{ .name = "content-type", .value = "application/octet-stream" }, // static-table name!
        });

        const ev_hdr = try s.readEvent(arena);
        try testing.expect(ev_hdr == .headers and !ev_hdr.headers.end_stream);
        var saw_urgency = false;
        for (ev_hdr.headers.headers) |h| {
            if (std.mem.eql(u8, h.name, "x-seen-urgency") and std.mem.eql(u8, h.value, "1-inc")) saw_urgency = true;
        }
        try testing.expect(saw_urgency);

        var body_out: [64]u8 = undefined;
        var total_n: usize = 0;
        while (true) {
            const n = try s.readBody(body_out[total_n..]);
            if (n == 0) break;
            total_n += n;
        }
        try testing.expectEqualStrings("chunk-1+chunk-2", body_out[0..total_n]);

        const ev_tr = try s.readEvent(arena);
        try testing.expect(ev_tr == .headers and ev_tr.headers.end_stream);
        var verified = false;
        for (ev_tr.headers.headers) |h| {
            if (std.mem.eql(u8, h.name, "x-verified-sha256") and std.mem.eql(u8, h.value, "deadbeef")) verified = true;
        }
        try testing.expect(verified);
    }

    // Case C: RFC 8441 Extended CONNECT (`:protocol = websocket`) full-duplex ping-pong!
    {
        const ws = try client.tryOpenStream(.{
            .method = "CONNECT",
            .protocol = "websocket",
            .scheme = "https",
            .path = "/realtime",
            .authority = "edge.example.com",
            .headers = &.{.{ .name = "sec-websocket-protocol", .value = "chat.v1" }},
        }, false);
        defer ws.close();

        // Server flushes 200 HEADERS immediately before client sends any DATA!
        const ev_ws = try ws.readEvent(arena);
        try testing.expect(ev_ws == .headers and !ev_ws.headers.end_stream);
        try testing.expectEqualStrings("200", ev_ws.headers.headers[0].value);

        var rx: [64]u8 = undefined;
        try ws.send("hello-ws", false);
        const want1 = "ws-echo:hello-ws";
        var n1: usize = 0;
        while (n1 < want1.len) {
            const got = try ws.readBody(rx[n1..]);
            if (got == 0) break;
            n1 += got;
        }
        try testing.expectEqualStrings(want1, rx[0..n1]);

        try ws.send("bye-ws", true);
        var n2: usize = 0;
        while (true) {
            const got = try ws.readBody(rx[n2..]);
            if (got == 0) break;
            n2 += got;
        }
        try testing.expectEqualStrings("ws-echo:bye-ws", rx[0..n2]);
    }
}
