//! Minimal end-to-end demo: an h2 server + client over a plain socketpair (no
//! TLS). Builds with `zig build example` and prints the echoed response.
//!
//! This is the same shape the gRPC unary-echo test exercises, as a standalone
//! program — a smoke test that the public API wires together.

const std = @import("std");
const h2 = @import("zig_http2");

const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("unistd.h");
});

fn echoHandler(ctx: *h2.Context) anyerror!void {
    ctx.res.status(200);
    try ctx.res.header("content-type", "text/plain");
    if (ctx.body_reader) |br| {
        var tmp: [256]u8 = undefined;
        while (true) {
            const n = try br.read(&tmp);
            if (n == 0) break;
            try ctx.res.write(tmp[0..n]);
        }
    }
    try ctx.res.finish();
}

fn serveFd(srv: *h2.Server, fd: std.posix.fd_t) void {
    defer _ = c.close(fd);
    const stream: std.Io.net.Stream = .{ .socket = .{
        .handle = fd,
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(srv.io, &rbuf);
    var sw = stream.writer(srv.io, &wbuf);
    h2.serveConn(srv, &sr.interface, &sw.interface, null, "https");
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var fds: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: h2.Server = .{ .io = io, .gpa = gpa, .handler = echoHandler };
    const th = try std.Thread.spawn(.{}, serveFd, .{ &srv, fds[0] });
    // Shutdown is LIFO: close the client end first so the server's read loop
    // sees EOF and exits, then join (otherwise join blocks the idle timeout).
    defer th.join();
    defer _ = c.close(fds[1]);

    const peer: std.Io.net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = peer.reader(io, &rbuf);
    var sw = peer.writer(io, &wbuf);

    var client: h2.Client = undefined;
    try client.init(io, gpa, &sr.interface, &sw.interface);
    defer client.deinit();

    const stream = try client.openStream(.{ .path = "/echo", .method = "POST" }, false);
    try stream.send("hello over h2", true);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var body = std.ArrayList(u8).empty;
    defer body.deinit(gpa);
    var done = false;
    while (!done) {
        switch (try stream.readEvent(arena)) {
            .data => |d| {
                try body.appendSlice(gpa, d.payload);
                if (d.end_stream) done = true;
            },
            .headers => |h| if (h.end_stream) {
                done = true;
            },
            .rst, .goaway => return error.UnexpectedStreamEnd,
        }
    }
    std.debug.print("echoed: {s}\n", .{body.items});
}
