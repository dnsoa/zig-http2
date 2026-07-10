//! Protocol-agnostic HTTP types used by the HTTP/2 server driver. These have
//! **no transport dependency** (no TLS, no sockets), so the driver can run over
//! any `std.Io.Reader`/`Writer` pair.
//!
//! The model is streaming: a handler accumulates response headers, then writes
//! the body incrementally; framing (DATA frames + END_STREAM) is the driver's
//! concern. Trailers are supported for gRPC (`grpc-status`/`grpc-message`).

const std = @import("std");

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Request = struct {
    method: []const u8,
    target: []const u8,
    /// HTTP minor version (0 or 1 for HTTP/1.0 / HTTP/1.1). For H2 this is left
    /// at 0; callers that care should look at the driver instead.
    minor_version: u8,
    headers: []const Header,
    content_length: ?u64,
    keep_alive: bool,

    pub fn get(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
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
        self.head_sent = true;
        try self.sink.vtable.sendHead(self.sink.ctx, self);
    }

    /// Writes a body chunk, streaming it to the client immediately.
    pub fn write(self: *Response, bytes: []const u8) !void {
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
    pub fn send(self: *Response, code: u16, content_type: []const u8, body: []const u8) !void {
        self.status(code);
        try self.header("content-type", content_type);
        self.setContentLength(body.len);
        try self.write(body);
    }

    pub fn finish(self: *Response) !void {
        if (self.finished) return;
        self.finished = true;
        try self.ensureHead();
        try self.sink.vtable.finish(self.sink.ctx, self);
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

    /// Arms a per-RPC deadline at an absolute timestamp. No-op if unsupported.
    pub fn setDeadline(self: *Context, deadline: std.Io.Timestamp) void {
        if (self.set_deadline_fn) |f| f(self.set_deadline_ctx.?, deadline);
    }

    /// Convenience: arm a deadline `ns` nanoseconds from now (e.g. from a parsed
    /// `grpc-timeout`). No-op if unsupported.
    pub fn setDeadlineIn(self: *Context, ns: u64) void {
        const now = std.Io.Timestamp.now(self.io, .awake);
        self.setDeadline(.{ .nanoseconds = now.nanoseconds + @as(i64, @intCast(ns)) });
    }
};

pub const Handler = *const fn (ctx: *Context) anyerror!void;
