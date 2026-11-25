//! zig-http2 — a dependency-free HTTP/2 (RFC 7540) server and client for Zig
//! 0.16's `std.Io` model. Transport-agnostic: callers supply any
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
//!   try s.send("ping", true);
//!   // s.readEvent(arena) yields .headers / .data / .rst / .goaway
//!   ```
//!
//! gRPC readiness: trailers, streaming request bodies (`ctx.body_reader`), and
//! bidirectional streaming (separate send/receive threads) are supported — the
//! shapes a gRPC server/client needs. Client limits: no PUSH_PROMISE (we
//! advertise ENABLE_PUSH=0 and tear down on a push), no PRIORITY, and `close()`
//! must be called per stream to reclaim it before `deinit`.

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
