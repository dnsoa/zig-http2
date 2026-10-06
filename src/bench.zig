//! Throughput benchmark for the write path (issue #12). Runs a server and a
//! client over a loopback TCP connection and times two shapes:
//!
//!   * unary  — many small request/response round trips (HEADERS + small DATA)
//!   * stream — one large body echoed back (DATA frames at max_frame_size)
//!
//! Build with `-Doptimize=ReleaseFast`; `zig build bench` does that by default.
//! Numbers are wall clock, so run it on an idle machine and compare runs rather
//! than trusting any single absolute figure.

const std = @import("std");
const h2 = @import("zig_http2");
const Io = std.Io;

const unary_iterations = 2000;
const stream_bytes = 8 << 20; // 8 MiB
const pingpong_iterations = 2000;

/// One `res.write` of the whole payload — the shape write coalescing targets:
/// the driver splits it into `max_frame_size` DATA frames internally.
fn bulkHandler(ctx: *h2.Context) anyerror!void {
    if (ctx.body_reader) |br| {
        var tmp: [16384]u8 = undefined;
        while (true) if (try br.read(&tmp) == 0) break;
    }
    ctx.res.status(200);
    try ctx.res.header("content-type", "application/grpc");
    try ctx.res.write(bulk_payload);
    try ctx.res.finish();
}

var bulk_payload: []const u8 = &.{};

fn dispatch(ctx: *h2.Context) anyerror!void {
    if (std.mem.eql(u8, ctx.req.path(), "/bulk")) return bulkHandler(ctx);
    return echoHandler(ctx);
}

fn echoHandler(ctx: *h2.Context) anyerror!void {
    ctx.res.status(200);
    try ctx.res.header("content-type", "application/grpc");
    if (ctx.body_reader) |br| {
        var tmp: [16384]u8 = undefined;
        while (true) {
            const n = try br.read(&tmp);
            if (n == 0) break;
            try ctx.res.write(tmp[0..n]);
        }
    }
    try ctx.res.finish();
}

const Server = struct {
    io: Io,
    listener: *Io.net.Server,
    srv: *h2.Server,

    fn run(self: *Server) void {
        var accepted = self.listener.accept(self.io) catch return;
        defer accepted.close(self.io);
        var rbuf: [64 << 10]u8 = undefined;
        var wbuf: [64 << 10]u8 = undefined;
        var sr = accepted.reader(self.io, &rbuf);
        var sw = accepted.writer(self.io, &wbuf);
        h2.serveConn(self.srv, &sr.interface, &sw.interface, null, "http");
    }
};

fn millis(start: i96, end: i96) f64 {
    return @as(f64, @floatFromInt(end - start)) / @as(f64, std.time.ns_per_ms);
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const addr0 = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr0.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.ip4.port;

    const bulk = try gpa.alloc(u8, stream_bytes);
    defer gpa.free(bulk);
    @memset(bulk, 'b');
    bulk_payload = bulk;

    var srv: h2.Server = .{ .io = io, .gpa = gpa, .handler = dispatch };
    var bsrv: Server = .{ .io = io, .listener = &listener, .srv = &srv };
    const th = try std.Thread.spawn(.{}, Server.run, .{&bsrv});

    var caddr = try Io.net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    var rbuf: [64 << 10]u8 = undefined;
    var wbuf: [64 << 10]u8 = undefined;
    var sr = cstream.reader(io, &rbuf);
    var sw = cstream.writer(io, &wbuf);

    var client: h2.Client = undefined;
    try client.init(io, gpa, &sr.interface, &sw.interface);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // --- unary: many small round trips ---
    const payload = "hello";
    var t0 = Io.Timestamp.now(io, .awake).nanoseconds;
    var i: usize = 0;
    while (i < unary_iterations) : (i += 1) {
        const s = try client.openStream(.{ .path = "/echo", .method = "POST" }, false);
        try s.send(payload, true);
        while (true) {
            switch (try s.readEvent(arena)) {
                .data => |d| if (d.end_stream) break,
                .headers => |hd| if (hd.end_stream) break,
                .rst, .goaway => return error.UnexpectedStreamEnd,
            }
        }
        s.close();
        _ = arena_state.reset(.retain_capacity);
    }
    var t1 = Io.Timestamp.now(io, .awake).nanoseconds;
    const unary_ms = millis(t0, t1);
    std.debug.print("unary  {d} RPCs  {d:.1} ms  {d:.0} RPC/s\n", .{
        unary_iterations,                                 unary_ms,
        @as(f64, unary_iterations) / (unary_ms / 1000.0),
    });

    // --- pingpong: same number of round trips, all on ONE stream ---
    // The difference against `unary` above is the per-stream cost: worker
    // spawn, H2Stream allocation, request arena, HEADERS encode/decode.
    t0 = Io.Timestamp.now(io, .awake).nanoseconds;
    const ps = try client.openStream(.{ .path = "/echo", .method = "POST" }, false);
    i = 0;
    while (i < pingpong_iterations) : (i += 1) {
        try ps.send(payload, false);
        while (true) {
            switch (try ps.readEvent(arena)) {
                .data => break,
                .headers => continue,
                .rst, .goaway => return error.UnexpectedStreamEnd,
            }
        }
        _ = arena_state.reset(.retain_capacity);
    }
    t1 = Io.Timestamp.now(io, .awake).nanoseconds;
    const pp_ms = millis(t0, t1);
    std.debug.print("pingpong {d} round trips on one stream  {d:.1} ms  {d:.0} RT/s\n", .{
        pingpong_iterations,                              pp_ms,
        @as(f64, pingpong_iterations) / (pp_ms / 1000.0),
    });
    ps.close();

    // --- stream: one large body up and back ---
    const body = try gpa.alloc(u8, stream_bytes);
    defer gpa.free(body);
    @memset(body, 'z');

    t0 = Io.Timestamp.now(io, .awake).nanoseconds;
    const s = try client.openStream(.{ .path = "/echo", .method = "POST" }, false);
    var sender: Sender = .{ .stream = s, .body = body };
    const sth = try std.Thread.spawn(.{}, Sender.run, .{&sender});
    var got: usize = 0;
    while (true) {
        switch (try s.readEvent(arena)) {
            .data => |d| {
                got += d.payload.len;
                if (d.end_stream) break;
            },
            .headers => |hd| if (hd.end_stream) break,
            .rst, .goaway => return error.UnexpectedStreamEnd,
        }
        _ = arena_state.reset(.retain_capacity);
    }
    sth.join();
    t1 = Io.Timestamp.now(io, .awake).nanoseconds;
    const stream_ms = millis(t0, t1);
    const mib = @as(f64, @floatFromInt(got)) / (1024.0 * 1024.0);
    std.debug.print("stream {d:.0} MiB echoed  {d:.1} ms  {d:.0} MiB/s\n", .{
        mib, stream_ms, mib / (stream_ms / 1000.0),
    });
    s.close();

    // --- bulk: server writes the whole payload in one res.write ---
    t0 = Io.Timestamp.now(io, .awake).nanoseconds;
    const bs = try client.openStream(.{ .path = "/bulk", .method = "POST" }, true);
    var bgot: usize = 0;
    while (true) {
        switch (try bs.readEvent(arena)) {
            .data => |d| {
                bgot += d.payload.len;
                if (d.end_stream) break;
            },
            .headers => |hd| if (hd.end_stream) break,
            .rst, .goaway => return error.UnexpectedStreamEnd,
        }
        _ = arena_state.reset(.retain_capacity);
    }
    t1 = Io.Timestamp.now(io, .awake).nanoseconds;
    const bulk_ms = millis(t0, t1);
    const bmib = @as(f64, @floatFromInt(bgot)) / (1024.0 * 1024.0);
    std.debug.print("bulk   {d:.0} MiB in one res.write  {d:.1} ms  {d:.0} MiB/s\n", .{
        bmib, bulk_ms, bmib / (bulk_ms / 1000.0),
    });
    bs.close();

    client.deinit();
    cstream.close(io);
    th.join();
}

const Sender = struct {
    stream: *h2.Stream,
    body: []const u8,
    fn run(self: *Sender) void {
        self.stream.send(self.body, true) catch {};
    }
};
