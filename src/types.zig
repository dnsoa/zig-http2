//! Protocol-agnostic HTTP types used by the HTTP/2 server driver. These have
//! **no transport dependency** (no TLS, no sockets), so the driver can run over
//! any `std.Io.Reader`/`Writer` pair.
//!
//! The model is streaming: a handler accumulates response headers, then writes
//! the body incrementally; framing (DATA frames + END_STREAM) is the driver's
//! concern. Trailers are supported for gRPC (`grpc-status`/`grpc-message`).

const std = @import("std");
const proto = @import("proto.zig");

pub const Header = struct { name: []const u8, value: []const u8 };
pub const StreamPriority = proto.StreamPriority;

pub const Request = struct {
    method: []const u8,
    target: []const u8,
    /// HTTP minor version (0 or 1 for HTTP/1.0 / HTTP/1.1). For H2 this is left
    /// at 0; callers that care should look at the driver instead.
    minor_version: u8,
    headers: []const Header,
    content_length: ?u64,
    keep_alive: bool,
    /// RFC 8441 Extended `CONNECT` `:protocol` pseudo-header (e.g. `"websocket"`),
    /// or `null` for standard HTTP requests.
    protocol: ?[]const u8 = null,
    /// RFC 9218 Extensible Priority parameters parsed from the `priority` header.
    priority: StreamPriority = .{},
    /// Validated request trailers populated once the request body reaches EOF.
    trailers: []const Header = &.{},

    pub fn get(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn getTrailer(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.trailers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn path(self: *const Request) []const u8 {
        const q = std.mem.indexOfScalar(u8, self.target, '?') orelse return self.target;
        return self.target[0..q];
    }
};

/// Protocol-agnostic body/head emission backend behind `Response`. The HTTP/2
/// driver supplies a sink bound to a stream. Keeping this a vtable (not a tagged
/// union) means these shared types never import the driver, so there is no
/// module cycle.
pub const Sink = struct {
    ctx: *anyopaque,
    vtable: *const Vtable,

    pub const Vtable = struct {
        /// Emit the response head (status + headers). Called once, lazily, on the
        /// first body write or on finish.
        sendHead: *const fn (ctx: *anyopaque, res: *Response) anyerror!void,
        /// Emit one body chunk (already counted in `res.body_bytes`).
        writeBody: *const fn (ctx: *anyopaque, res: *Response, bytes: []const u8) anyerror!void,
        /// Flush/terminate the response (final chunk, END_STREAM, etc.).
        finish: *const fn (ctx: *anyopaque, res: *Response) anyerror!void,
        /// Optional coalesced fast path: emit the response head, complete body
        /// (may be empty), and END_STREAM together in as few flushes as possible.
        /// Falls back to `sendHead` + `writeBody` + `finish` when null.
        sendComplete: ?*const fn (ctx: *anyopaque, res: *Response, body: []const u8) anyerror!void = null,
        /// Optional `1xx` informational HEADERS emission (e.g. `103 Early Hints`,
        /// `100 Continue`) before the final response head is sent.
        sendInformational: ?*const fn (ctx: *anyopaque, status_code: u16, headers: []const Header) anyerror!void = null,
    };
};

/// Streaming response writer. Headers are accumulated, then flushed lazily on
/// the first body write (or on `finish`) via the `Sink`.
pub const Response = struct {
    arena: std.mem.Allocator,
    sink: Sink,
    status_code: u16 = 200,
    extra: std.ArrayList(Header) = .empty,
    /// Trailing header fields, sent after the body (HTTP/2 trailers). Used by
    /// gRPC for `grpc-status`/`grpc-message`.
    trailers: std.ArrayList(Header) = .empty,
    content_length: ?u64 = null,
    minor_version: u8 = 1,
    keep_alive: bool = true,

    head_sent: bool = false,
    /// Guard set by `finish()` so the trailing END_STREAM (and any trailers) is
    /// emitted exactly once. The driver also calls `finish()` after the handler
    /// returns, so it must be idempotent — otherwise a handler that finishes
    /// itself (e.g. setting gRPC trailers) triggers a duplicate END_STREAM.
    finished: bool = false,
    /// Total body bytes written (for access logging / metrics).
    body_bytes: u64 = 0,

    pub fn status(self: *Response, code: u16) void {
        self.status_code = code;
    }

    pub fn header(self: *Response, name: []const u8, value: []const u8) !void {
        try self.extra.append(self.arena, .{
            .name = try self.arena.dupe(u8, name),
            .value = try self.arena.dupe(u8, value),
        });
    }

    pub fn setContentLength(self: *Response, n: u64) void {
        self.content_length = n;
    }

    /// Adds a trailing header (emitted after the body as HTTP/2 trailers).
    pub fn trailer(self: *Response, name: []const u8, value: []const u8) !void {
        try self.trailers.append(self.arena, .{
            .name = try self.arena.dupe(u8, name),
            .value = try self.arena.dupe(u8, value),
        });
    }

    fn ensureHead(self: *Response) !void {
        if (self.head_sent) return;
        try self.sink.vtable.sendHead(self.sink.ctx, self);
        self.head_sent = true;
    }

    /// Explicitly flushes the final response HEADERS (without `END_STREAM`)
    /// before any body bytes are written — e.g. to complete an RFC 8441 Extended
    /// `CONNECT` (`200`) handshake before waiting on full-duplex client frames.
    pub fn flushHead(self: *Response) !void {
        if (self.finished) return error.ResponseFinished;
        try self.ensureHead();
    }

    /// Emits an HTTP `1xx` informational response block (`100..199`, excluding
    /// `101` which RFC 9113 §8.3.2 forbids in HTTP/2) immediately without
    /// marking the final response head as sent.
    pub fn sendInformational(self: *Response, status_code: u16, headers: []const Header) !void {
        if (self.head_sent or self.finished) return error.HeadAlreadySent;
        if (status_code < 100 or status_code > 199 or status_code == 101) {
            return error.InvalidInformationalStatus;
        }
        for (headers) |h| {
            if (h.name.len == 0 or h.name[0] == ':') return error.InvalidInformationalHeader;
            for (h.name) |ch| {
                if (!proto.isTokenChar(ch)) return error.InvalidInformationalHeader;
            }
            if (!proto.isValidFieldValue(h.value)) return error.InvalidInformationalHeader;
            if (proto.isConnectionSpecificHeader(h.name) or
                std.ascii.eqlIgnoreCase(h.name, "te") or
                std.ascii.eqlIgnoreCase(h.name, "content-length"))
            {
                return error.InvalidInformationalHeader;
            }
        }
        if (self.sink.vtable.sendInformational) |send_info| {
            try send_info(self.sink.ctx, status_code, headers);
        }
    }

    /// Convenience helper for RFC 8297 `103 Early Hints` (e.g. `Link: <...>; rel=preload`).
    pub fn sendEarlyHints(self: *Response, headers: []const Header) !void {
        return self.sendInformational(103, headers);
    }

    /// Writes a body chunk, streaming it to the client immediately.
    pub fn write(self: *Response, bytes: []const u8) !void {
        if (self.finished) return error.ResponseFinished;
        try self.ensureHead();
        if (bytes.len == 0) return;
        self.body_bytes += bytes.len;
        try self.sink.vtable.writeBody(self.sink.ctx, self, bytes);
    }

    pub fn print(self: *Response, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.allocPrint(self.arena, fmt, args);
        try self.write(s);
    }

    /// Convenience: send a complete response body with a known length.
    /// Uses the sink's coalesced `sendComplete` fast path when available so
    /// HEADERS + final DATA(END_STREAM) (or HEADERS(END_STREAM) when empty)
    /// are flushed together.
    pub fn send(self: *Response, code: u16, content_type: []const u8, body: []const u8) !void {
        if (self.finished) return error.ResponseFinished;
        self.status(code);
        try self.header("content-type", content_type);
        self.setContentLength(body.len);
        if (!self.head_sent and self.trailers.items.len == 0) {
            if (self.sink.vtable.sendComplete) |send_complete| {
                self.body_bytes += body.len;
                try send_complete(self.sink.ctx, self, body);
                self.head_sent = true;
                self.finished = true;
                return;
            }
        }
        try self.write(body);
    }

    pub fn finish(self: *Response) !void {
        if (self.finished) return;
        if (!self.head_sent and self.trailers.items.len == 0) {
            if (self.sink.vtable.sendComplete) |send_complete| {
                try send_complete(self.sink.ctx, self, "");
                self.head_sent = true;
                self.finished = true;
                return;
            }
        }
        try self.ensureHead();
        try self.sink.vtable.finish(self.sink.ctx, self);
        self.finished = true;
    }
};

/// Incremental request-body reader for streaming requests (gRPC client-streaming
/// / bidi). The driver supplies this when it delivers request DATA to a
/// still-running handler instead of buffering the whole body. `read` returns 0
/// at end-of-body (peer half-close); errors on transport teardown.
pub const BodyReader = struct {
    ctx: *anyopaque,
    readFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!usize,

    pub fn read(self: BodyReader, buf: []u8) anyerror!usize {
        return self.readFn(self.ctx, buf);
    }
};

pub const Context = struct {
    req: *Request,
    res: *Response,
    arena: std.mem.Allocator,
    io: std.Io,
    /// Opaque pointer to shared application state (set via Server.userdata).
    userdata: ?*anyopaque,
    /// Streaming request-body reader. The HTTP/2 driver sets this so the handler
    /// can pull the body incrementally; null when there is no body.
    body_reader: ?BodyReader = null,
    /// Whether the request carries a body, as determined by the driver (HTTP/2
    /// END_STREAM framing). A request may have a body with no content-length
    /// header (H2), so consult this rather than sniffing headers.
    has_body: bool = false,
    /// Client (peer) IP as a string, when the driver knows it — used to build
    /// X-Forwarded-For. Null when unavailable.
    client_ip: ?[]const u8 = null,
    /// Scheme this node received the request on ("http" / "https") — used for
    /// X-Forwarded-Proto. Secure (TLS) is `!eql(scheme, "http")`.
    scheme: []const u8 = "http",

    /// Per-RPC deadline support. The HTTP/2 driver arms a watchdog that aborts
    /// a blocking `body_reader.read()`/`res.write()` with `error.DeadlineExceeded`
    /// once `deadline` passes. Null when the driver doesn't provide it.
    set_deadline_ctx: ?*anyopaque = null,
    set_deadline_fn: ?*const fn (ctx: *anyopaque, deadline: std.Io.Timestamp) void = null,

    /// Optional driver callback returning received request trailers once
    /// `END_STREAM` has been observed on the request body.
    trailers_ctx: ?*anyopaque = null,
    trailers_fn: ?*const fn (ctx: *anyopaque) []const Header = null,

    /// Arms a per-RPC deadline at an absolute timestamp. No-op if unsupported.
    pub fn setDeadline(self: *Context, deadline: std.Io.Timestamp) void {
        if (self.set_deadline_fn) |f| f(self.set_deadline_ctx.?, deadline);
    }

    /// Convenience: arm a deadline `ns` nanoseconds from now (e.g. from a parsed
    /// `grpc-timeout`). No-op if unsupported.
    pub fn setDeadlineIn(self: *Context, ns: u64) void {
        const now = std.Io.Timestamp.now(self.io, .awake);
        self.setDeadline(.{ .nanoseconds = now.nanoseconds + @as(i96, ns) });
    }

    /// Returns validated request trailers received on this stream (empty until
    /// the peer closes its send half with trailing `HEADERS(END_STREAM)`).
    pub fn trailers(self: *const Context) []const Header {
        if (self.trailers_fn) |f| return f(self.trailers_ctx.?);
        return self.req.trailers;
    }
};

pub const Handler = *const fn (ctx: *Context) anyerror!void;

test "Context.setDeadlineIn handles u64 values above maxInt(i64) without panicking (#23)" {
    const Capture = struct {
        seen: ?std.Io.Timestamp = null,
        fn set(ctx: *anyopaque, dl: std.Io.Timestamp) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.seen = dl;
        }
    };
    var cap: Capture = .{};
    var req: Request = .{
        .method = "GET",
        .target = "/",
        .minor_version = 0,
        .headers = &.{},
        .content_length = null,
        .keep_alive = true,
    };
    var res: Response = undefined;
    var ctx: Context = .{
        .req = &req,
        .res = &res,
        .arena = std.testing.allocator,
        .io = std.testing.io,
        .userdata = null,
        .set_deadline_ctx = &cap,
        .set_deadline_fn = Capture.set,
    };
    const big_ns: u64 = @as(u64, std.math.maxInt(i64)) + 4096;
    ctx.setDeadlineIn(big_ns);
    try std.testing.expect(cap.seen != null);
    try std.testing.expect(cap.seen.?.nanoseconds >= @as(i96, big_ns));
}

test "Response.write and Response.send reject writes after finish()" {
    const DummySink = struct {
        heads: usize = 0,
        writes: usize = 0,
        finishes: usize = 0,
        fn sendHead(ctx: *anyopaque, _: *Response) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.heads += 1;
        }
        fn writeBody(ctx: *anyopaque, _: *Response, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.writes += 1;
        }
        fn finish(ctx: *anyopaque, _: *Response) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.finishes += 1;
        }
    };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var ds: DummySink = .{};
    const vtable: Sink.Vtable = .{
        .sendHead = DummySink.sendHead,
        .writeBody = DummySink.writeBody,
        .finish = DummySink.finish,
    };
    var res: Response = .{
        .arena = arena_state.allocator(),
        .sink = .{ .ctx = &ds, .vtable = &vtable },
    };
    try res.write("hello");
    try res.finish();
    try std.testing.expectError(error.ResponseFinished, res.write("late"));
    try std.testing.expectError(error.ResponseFinished, res.send(200, "text/plain", "late"));
    try std.testing.expectEqual(@as(usize, 1), ds.heads);
    try std.testing.expectEqual(@as(usize, 1), ds.writes);
    try std.testing.expectEqual(@as(usize, 1), ds.finishes);
}

test "Response.sendInformational and sendEarlyHints enforce RFC 9113 / RFC 9110 rules" {
    const InfoSink = struct {
        infos: usize = 0,
        last_code: u16 = 0,
        heads: usize = 0,
        fn sendInfo(ctx: *anyopaque, code: u16, _: []const Header) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.infos += 1;
            self.last_code = code;
        }
        fn sendHead(ctx: *anyopaque, _: *Response) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.heads += 1;
        }
        fn writeBody(_: *anyopaque, _: *Response, _: []const u8) anyerror!void {}
        fn finish(_: *anyopaque, _: *Response) anyerror!void {}
    };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var is: InfoSink = .{};
    const vtable: Sink.Vtable = .{
        .sendHead = InfoSink.sendHead,
        .writeBody = InfoSink.writeBody,
        .finish = InfoSink.finish,
        .sendInformational = InfoSink.sendInfo,
    };
    var res: Response = .{
        .arena = arena_state.allocator(),
        .sink = .{ .ctx = &is, .vtable = &vtable },
    };
    // Invalid codes (101, 99, 200) rejected.
    try std.testing.expectError(error.InvalidInformationalStatus, res.sendInformational(101, &.{}));
    try std.testing.expectError(error.InvalidInformationalStatus, res.sendInformational(99, &.{}));
    try std.testing.expectError(error.InvalidInformationalStatus, res.sendInformational(200, &.{}));
    // Forbidden headers (pseudo, content-length, connection, te) rejected.
    try std.testing.expectError(error.InvalidInformationalHeader, res.sendEarlyHints(&.{.{ .name = ":status", .value = "103" }}));
    try std.testing.expectError(error.InvalidInformationalHeader, res.sendEarlyHints(&.{.{ .name = "content-length", .value = "0" }}));
    try std.testing.expectError(error.InvalidInformationalHeader, res.sendEarlyHints(&.{.{ .name = "connection", .value = "close" }}));

    // Valid 103 + 100 leave head_sent false; flushHead sends final head and blocks further 1xx.
    try res.sendEarlyHints(&.{.{ .name = "link", .value = "</app.css>; rel=preload; as=style" }});
    try res.sendInformational(100, &.{});
    try std.testing.expectEqual(@as(usize, 2), is.infos);
    try std.testing.expectEqual(@as(u16, 100), is.last_code);
    try std.testing.expect(!res.head_sent);

    try res.flushHead();
    try std.testing.expect(res.head_sent);
    try std.testing.expectEqual(@as(usize, 1), is.heads);
    try std.testing.expectError(error.HeadAlreadySent, res.sendEarlyHints(&.{}));
}
