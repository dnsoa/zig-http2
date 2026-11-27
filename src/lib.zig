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
