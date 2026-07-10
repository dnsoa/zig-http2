//! HTTP/2 server (RFC 7540) over an already-established transport, reached when
//! ALPN negotiates "h2" (or directly over any duplex stream). Transport-agnostic:
//! the caller hands us `*std.Io.Reader`/`*std.Io.Writer` (TLS-wrapped for real
//! connections, or a plain socketpair in tests). Cleartext h2c is not specially
//! handled — the caller decides what transport to wrap.
//!
//! Concurrency: the connection's thread is the single **reader** — it owns frame
//! parsing and the HPACK decoder (HEADERS must be decoded in on-wire order, so
//! no lock is needed there). Each request that completes spawns a **worker
//! thread** running the handler with a `Response` whose sink frames DATA on that
//! stream. Every frame write — control frames from the reader, HEADERS/DATA from
//! workers — is serialized through one `ConnWriter` mutex (one transport permits
//! one concurrent reader + one writer, never two writers). Outbound DATA obeys
//! per-stream and connection flow-control windows; a worker with an exhausted
//! window blocks on a condition until a WINDOW_UPDATE (or teardown) wakes it.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const types = @import("types.zig");
const hpack = @import("hpack.zig");

const log = std.log.scoped(.http2);

// Shared HTTP/2 wire primitives live in proto.zig so the client reuses them.
// Aliased here so the rest of this file reads against short local names.
const proto2 = @import("proto.zig");
const preface = proto2.preface;
const FrameType = proto2.FrameType;
const flag_ack = proto2.flag_ack;
const flag_end_stream = proto2.flag_end_stream;
const flag_end_headers = proto2.flag_end_headers;
const flag_padded = proto2.flag_padded;
const flag_priority = proto2.flag_priority;
const ErrorCode = proto2.ErrorCode;
const set_header_table_size = proto2.set_header_table_size;
const set_enable_push = proto2.set_enable_push;
const set_max_concurrent_streams = proto2.set_max_concurrent_streams;
const set_initial_window_size = proto2.set_initial_window_size;
const set_max_frame_size = proto2.set_max_frame_size;
const our_max_frame_size = proto2.our_max_frame_size;
const our_header_table_size = proto2.our_header_table_size;
const default_window = proto2.default_window;
const ParsedHeader = proto2.ParsedHeader;
const putHeader = proto2.putHeader;
const parseHeader = proto2.parseHeader;
const putSetting = proto2.putSetting;

// Server-only limit (not shared).
const our_max_concurrent: u32 = 128;

const Settings = struct {
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
};

/// Timeouts and limits for a server connection.
pub const Config = struct {
    /// Bound on reading one request head / h2 frame payload once bytes are
    /// expected (anti-slowloris). 0 = unbounded.
    head_timeout_ms: u64 = 30_000,
    /// Keep-alive: max idle wait for the next frame header before the connection
    /// is closed. 0 = unbounded.
    idle_timeout_ms: u64 = 180_000,
    /// Max concurrent streams we serve — advertised as
    /// SETTINGS_MAX_CONCURRENT_STREAMS and enforced on inbound HEADERS.
    max_concurrent_streams: u32 = our_max_concurrent,
    /// SETTINGS_MAX_FRAME_SIZE we advertise and enforce inbound (clamped to the
    /// RFC range 16384..16777215). Larger frames cut per-message overhead.
    max_frame_size: u32 = our_max_frame_size,
    /// SETTINGS_INITIAL_WINDOW_SIZE we advertise for stream-level flow control
    /// on DATA we receive — the peer's initial send window into us (0..2^31-1).
    initial_window_size: u32 = @intCast(default_window),
};

/// Effective inbound/advertised MAX_FRAME_SIZE, clamped to the RFC 7540 §6.5.2
/// range so a misconfigured caller can't put invalid values on the wire.
fn effectiveMaxFrameSize(cfg: Config) u32 {
    return @min(@max(cfg.max_frame_size, our_max_frame_size), 16777215);
}

/// A server value the caller fills in; `serveConn` reads its fields. There is no
/// accept loop and no TLS here — wrap your own transport and call `serveConn`
/// per accepted connection.
pub const Server = struct {
    io: Io,
    gpa: std.mem.Allocator,
    handler: types.Handler,
    config: Config = .{},
    /// Opaque shared state handed to each handler via Context.userdata.
    userdata: ?*anyopaque = null,
    /// Signal-safe stop flag. When set, new streams are refused (RST
    /// REFUSED_STREAM) and the read loop drains in-flight workers.
    stop: std.atomic.Value(bool) = .init(false),
};

const TimedOp = union(enum) { work: anyerror!void, timer: void };

fn timerThunk(io: Io, ms: u64) void {
    Io.sleep(io, .{ .nanoseconds = @intCast(ms * std.time.ns_per_ms) }, .awake) catch {};
}

/// Runs blocking `f(args...)` (must return anyerror!void) raced against a `ms`
/// deadline; `error.Timeout` when the deadline wins. The loser is canceled —
/// the std.Io backend interrupts the blocked syscall (one-shot; callers close
/// the connection on timeout rather than retrying). `ms == 0` = no deadline.
pub fn runTimed(io: Io, ms: u64, f: anytype, args: anytype) anyerror!void {
    if (ms == 0) return @call(.auto, f, args);
    var buf: [2]TimedOp = undefined;
    var sel = Io.Select(TimedOp).init(io, &buf);
    sel.concurrent(.work, f, args) catch return @call(.auto, f, args);
    sel.concurrent(.timer, timerThunk, .{ io, ms }) catch {
        while (sel.cancel()) |_| {}
        return @call(.auto, f, args);
    };
    const first = try sel.await();
    var ok = switch (first) {
        .work => |r| if (r) |_| true else |_| false,
        .timer => false,
    };
    var work_err: ?anyerror = switch (first) {
        .work => |r| if (r) |_| null else |e| e,
        .timer => null,
    };
    while (sel.cancel()) |leftover| switch (leftover) {
        .work => |r| if (r) |_| {
            ok = true;
        } else |e| {
            if (work_err == null) work_err = e;
        },
        .timer => {},
    };
    if (ok) return;
    return switch (first) {
        .timer => error.Timeout,
        .work => work_err.?,
    };
}

/// Serializes all frame writes to the shared transport.
const ConnWriter = struct {
    io: Io,
    w: *Io.Writer,
    mu: Io.Mutex = .init,

    fn lock(self: *ConnWriter) void {
        self.mu.lockUncancelable(self.io);
    }
    fn unlock(self: *ConnWriter) void {
        self.mu.unlock(self.io);
    }

    /// Writes one frame; assumes the writer lock is already held. No flush.
    fn frameLocked(self: *ConnWriter, ftype: FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        var hdr: [9]u8 = undefined;
        putHeader(&hdr, payload.len, ftype, flags, sid);
        try self.w.writeAll(&hdr);
        if (payload.len > 0) try self.w.writeAll(payload);
    }

    /// Writes one self-contained frame (lock + flush).
    fn frame(self: *ConnWriter, ftype: FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        self.lock();
        defer self.unlock();
        try self.frameLocked(ftype, flags, sid, payload);
        try self.w.flush();
    }
};

/// One HTTP/2 stream + its request. Lives on the gpa; freed by its worker.
const H2Stream = struct {
    conn: *Connection,
    id: u31,
    arena_state: std.heap.ArenaAllocator,
    req: types.Request,
    /// Flow-control window for DATA we send, guarded by `conn.send_mu`.
    send_window: i64,
    reset: std.atomic.Value(bool) = .init(false),
    /// Whether the request has a body (no END_STREAM on HEADERS). Set on the
    /// reader thread before the worker is spawned; read once by the worker.
    has_body: bool = false,

    /// Request-body channel. The worker is spawned as soon as HEADERS decode;
    /// the reader thread appends request DATA here as it arrives and the worker
    /// drains it via `streamRead` (a `types.BodyReader` exposed as
    /// `ctx.body_reader`). A bodyless request (END_STREAM on HEADERS) has
    /// `rx_eof` preset so the reader returns 0 immediately. One body path for
    /// every request.
    rx_mu: Io.Mutex = .init,
    rx_cond: Io.Condition = .init,
    rx_buf: std.ArrayList(u8) = .empty, // gpa-backed; freed by the worker
    rx_off: usize = 0,
    rx_eof: bool = false,

    /// Per-RPC deadline (absolute awake-clock timestamp). When set, a watchdog
    /// thread aborts blocking body/response I/O past it with DeadlineExceeded.
    deadline: ?Io.Timestamp = null,
    timed_out: std.atomic.Value(bool) = .init(false),
    /// Set by the worker as it exits so the watchdog stops early (it's joined
    /// before the stream is freed, so its `*H2Stream` stays valid until then).
    done: std.atomic.Value(bool) = .init(false),
    deadline_thread: ?std.Thread = null,

    /// Arms (or tightens) the per-RPC deadline, spawning the watchdog once.
    fn armDeadline(self: *H2Stream, deadline: Io.Timestamp) void {
        self.deadline = deadline;
        if (self.deadline_thread == null) {
            self.deadline_thread = std.Thread.spawn(.{}, deadlineWatchdog, .{self}) catch null;
        }
    }

    fn arena(self: *H2Stream) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// `types.BodyReader` backend: blocks until request bytes are available,
    /// returns 0 at END_STREAM, errors on reset/teardown.
    fn streamRead(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *H2Stream = @alignCast(@ptrCast(ctx));
        const conn = self.conn;
        self.rx_mu.lockUncancelable(conn.io);
        defer self.rx_mu.unlock(conn.io);
        while (true) {
            if (self.timed_out.load(.acquire)) return error.DeadlineExceeded;
            if (self.reset.load(.acquire) or conn.closing.load(.acquire)) return error.StreamReset;
            const avail = self.rx_buf.items.len - self.rx_off;
            if (avail > 0) {
                const n = @min(avail, buf.len);
                @memcpy(buf[0..n], self.rx_buf.items[self.rx_off..][0..n]);
                self.rx_off += n;
                if (self.rx_off == self.rx_buf.items.len) {
                    self.rx_buf.clearRetainingCapacity();
                    self.rx_off = 0;
                }
                return n;
            }
            if (self.rx_eof) return 0;
            self.rx_cond.waitUncancelable(conn.io, &self.rx_mu);
        }
    }

    fn bodyReader(self: *H2Stream) types.BodyReader {
        return .{ .ctx = self, .readFn = streamRead };
    }

    /// Sends `data` as flow-controlled DATA frames (never END_STREAM). Blocks
    /// while the send window is empty; errors if the stream/connection tears down.
    fn sendBody(self: *H2Stream, data: []const u8) !void {
        const conn = self.conn;
        var off: usize = 0;
        while (off < data.len) {
            conn.send_mu.lockUncancelable(conn.io);
            const n = blk: while (true) {
                if (self.timed_out.load(.acquire)) {
                    conn.send_mu.unlock(conn.io);
                    return error.DeadlineExceeded;
                }
                if (self.reset.load(.acquire) or conn.closing.load(.acquire)) {
                    conn.send_mu.unlock(conn.io);
                    return error.StreamReset;
                }
                const avail = @min(self.send_window, conn.send_window);
                if (avail > 0) {
                    const want: i64 = @min(@as(i64, @intCast(data.len - off)), @min(avail, @as(i64, conn.peer.max_frame_size)));
                    self.send_window -= want;
                    conn.send_window -= want;
                    break :blk @as(usize, @intCast(want));
                }
                conn.send_cond.waitUncancelable(conn.io, &conn.send_mu);
            };
            conn.send_mu.unlock(conn.io);
            try conn.cw.frame(.data, 0, self.id, data[off .. off + n]);
            off += n;
        }
    }

    fn endStream(self: *H2Stream) !void {
        try self.conn.cw.frame(.data, flag_end_stream, self.id, "");
    }
};

/// `types.Context.setDeadline` backend: arms the stream's deadline watchdog.
fn h2SetDeadline(opaque_ctx: *anyopaque, deadline: Io.Timestamp) void {
    const st: *H2Stream = @ptrCast(@alignCast(opaque_ctx));
    st.armDeadline(deadline);
}

/// Polls the stream's deadline; on expiry flips `timed_out`+`reset` and wakes
/// any body/response I/O blocked on `rx_cond`/`send_cond`. Runs only while the
/// worker owns the stream — it sets `done` and joins us before freeing it.
fn deadlineWatchdog(st: *H2Stream) void {
    const conn = st.conn;
    while (!st.done.load(.acquire)) {
        if (st.deadline) |dl| {
            if (Io.Timestamp.now(conn.io, .awake).nanoseconds >= dl.nanoseconds) {
                st.timed_out.store(true, .release);
                st.reset.store(true, .release);
                st.rx_mu.lockUncancelable(conn.io);
                st.rx_cond.broadcast(conn.io);
                st.rx_mu.unlock(conn.io);
                conn.send_mu.lockUncancelable(conn.io);
                conn.send_cond.broadcast(conn.io);
                conn.send_mu.unlock(conn.io);
                return;
            }
        } else return;
        Io.sleep(conn.io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
}

/// Response sink that frames a handler's output onto an HTTP/2 stream.
const H2Sink = struct {
    stream: *H2Stream,

    const vtable: types.Sink.Vtable = .{ .sendHead = sendHead, .writeBody = writeBody, .finish = finish };

    fn sink(self: *H2Sink) types.Sink {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn sendHead(ctx: *anyopaque, res: *types.Response) anyerror!void {
        const self: *H2Sink = @ptrCast(@alignCast(ctx));
        var block: std.ArrayList(u8) = .empty;
        const hdrs = try buildResponseHeaders(res);
        try hpack.Encoder.encodeResponse(res.arena, &block, res.status_code, hdrs);
        try self.stream.conn.writeHeaders(self.stream.id, block.items, false);
    }

    fn writeBody(ctx: *anyopaque, _: *types.Response, bytes: []const u8) anyerror!void {
        const self: *H2Sink = @ptrCast(@alignCast(ctx));
        try self.stream.sendBody(bytes);
    }

    fn finish(ctx: *anyopaque, res: *types.Response) anyerror!void {
        const self: *H2Sink = @ptrCast(@alignCast(ctx));
        if (res.trailers.items.len > 0) {
            // Trailing HEADERS carry END_STREAM (e.g. gRPC grpc-status).
            const items = res.trailers.items;
            const hdrs = try res.arena.alloc(hpack.Header, items.len);
            for (items, 0..) |h, i| hdrs[i] = .{ .name = h.name, .value = h.value };
            var block: std.ArrayList(u8) = .empty;
            try hpack.Encoder.encodeTrailers(res.arena, &block, hdrs);
            try self.stream.conn.writeHeaders(self.stream.id, block.items, true);
        } else {
            try self.stream.endStream();
        }
    }
};

fn buildResponseHeaders(res: *types.Response) ![]hpack.Header {
    const items = res.extra.items;
    const needs_content_length = res.content_length != null and !hasHeader(items, "content-length");
    const extra = if (needs_content_length) @as(usize, 1) else 0;
    const hdrs = try res.arena.alloc(hpack.Header, items.len + extra);
    for (items, 0..) |h, i| hdrs[i] = .{ .name = h.name, .value = h.value };
    if (needs_content_length) {
        hdrs[items.len] = .{
            .name = "content-length",
            .value = try std.fmt.allocPrint(res.arena, "{d}", .{res.content_length.?}),
        };
    }
    return hdrs;
}

fn hasHeader(headers: []const types.Header, name: []const u8) bool {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return true;
    }
    return false;
}

const Connection = struct {
    srv: *Server,
    gpa: std.mem.Allocator,
    io: Io,
    cw: ConnWriter,
    decoder: hpack.Decoder,
    peer: Settings = .{},
    /// Client IP + scheme for X-Forwarded-* (connection-wide, immutable).
    client_ip: ?[]const u8 = null,
    scheme: []const u8 = "http",

    // Flow control for DATA we send (connection-level + per-stream live here).
    send_mu: Io.Mutex = .init,
    send_cond: Io.Condition = .init,
    send_window: i64 = default_window,

    // Stream registry.
    streams_mu: Io.Mutex = .init,
    streams: std.AutoHashMapUnmanaged(u31, *H2Stream) = .empty,
    last_stream_id: u31 = 0,

    // Worker accounting (for graceful drain).
    workers_mu: Io.Mutex = .init,
    workers_cond: Io.Condition = .init,
    active_workers: u32 = 0,

    closing: std.atomic.Value(bool) = .init(false),

    fn deinit(self: *Connection) void {
        // Workers have all exited (drainWorkers ran) and removed their streams.
        self.streams.deinit(self.gpa);
        self.decoder.deinit();
    }

    fn sendOurSettings(self: *Connection) !void {
        const cfg = self.srv.config;
        var p: [30]u8 = undefined; // 5 entries * 6 bytes
        putSetting(p[0..6], set_enable_push, 0);
        putSetting(p[6..12], set_max_concurrent_streams, cfg.max_concurrent_streams);
        putSetting(p[12..18], set_header_table_size, our_header_table_size);
        putSetting(p[18..24], set_max_frame_size, effectiveMaxFrameSize(cfg));
        putSetting(p[24..30], set_initial_window_size, cfg.initial_window_size);
        try self.cw.frame(.settings, 0, 0, &p);
    }

    /// Wakes any worker blocked on a flow-control window (after WINDOW_UPDATE,
    /// reset, or teardown).
    fn wakeSenders(self: *Connection) void {
        self.send_mu.lockUncancelable(self.io);
        self.send_cond.broadcast(self.io);
        self.send_mu.unlock(self.io);
    }

    /// HEADERS (+ CONTINUATION when the block exceeds the peer's max frame size),
    /// emitted atomically so no other stream's frames interleave.
    fn writeHeaders(self: *Connection, sid: u31, block: []const u8, end_stream: bool) !void {
        const max = self.peer.max_frame_size;
        // END_STREAM rides the HEADERS frame (never CONTINUATION).
        const es: u8 = if (end_stream) flag_end_stream else 0;
        self.cw.lock();
        defer self.cw.unlock();
        if (block.len <= max) {
            try self.cw.frameLocked(.headers, flag_end_headers | es, sid, block);
        } else {
            try self.cw.frameLocked(.headers, es, sid, block[0..max]);
            var off: usize = max;
            while (off < block.len) {
                const end = @min(off + max, block.len);
                const last = end == block.len;
                try self.cw.frameLocked(.continuation, if (last) flag_end_headers else 0, sid, block[off..end]);
                off = end;
            }
        }
        try self.cw.w.flush();
    }

    /// Wakes every streaming worker blocked in `streamRead` (after teardown so
    /// they observe `closing` and exit). Safe lock order: streams_mu -> rx_mu.
    fn wakeReceivers(self: *Connection) void {
        self.streams_mu.lockUncancelable(self.io);
        var it = self.streams.valueIterator();
        while (it.next()) |stp| {
            const s = stp.*;
            s.rx_mu.lockUncancelable(self.io);
            s.rx_cond.broadcast(self.io);
            s.rx_mu.unlock(self.io);
        }
        self.streams_mu.unlock(self.io);
    }

    fn drainWorkers(self: *Connection) void {
        self.closing.store(true, .release);
        self.wakeSenders(); // release any window-blocked workers
        self.wakeReceivers(); // release any rx-blocked streaming workers
        self.workers_mu.lockUncancelable(self.io);
        while (self.active_workers > 0) self.workers_cond.waitUncancelable(self.io, &self.workers_mu);
        self.workers_mu.unlock(self.io);
    }
};

fn readSliceThunk(r: *Io.Reader, buf: []u8) anyerror!void {
    return r.readSliceAll(buf);
}

/// Deadline-bounded readSliceAll; skips the timer when the bytes are already
/// buffered (the common case for a payload right after its frame header).
fn readSliceTimed(conn: *Connection, r: *Io.Reader, buf: []u8, ms: u64) !void {
    if (r.bufferedLen() >= buf.len) return r.readSliceAll(buf);
    return runTimed(conn.io, ms, readSliceThunk, .{ r, buf });
}

/// Entry point: drive an HTTP/2 connection over `r`/`w` (any duplex transport).
pub fn serveConn(srv: *Server, r: *Io.Reader, w: *Io.Writer, client_ip: ?[]const u8, scheme: []const u8) void {
    var pf: [preface.len]u8 = undefined;
    runTimed(srv.io, srv.config.head_timeout_ms, readSliceThunk, .{ r, pf[0..] }) catch return;
    if (!std.mem.eql(u8, &pf, preface)) {
        log.warn("bad HTTP/2 preface", .{});
        return;
    }

    var conn: Connection = .{
        .srv = srv,
        .gpa = srv.gpa,
        .io = srv.io,
        .cw = .{ .io = srv.io, .w = w },
        .decoder = hpack.Decoder.init(srv.gpa, our_header_table_size),
        .client_ip = client_ip,
        .scheme = scheme,
    };
    defer conn.deinit();

    conn.sendOurSettings() catch return;
    readLoop(&conn, r);
    conn.drainWorkers();
}

fn readLoop(conn: *Connection, r: *Io.Reader) void {
    const gpa = conn.gpa;
    while (!conn.srv.stop.load(.acquire)) {
        // Idle deadline on the next frame header; a shorter deadline on the
        // payload it announces (a header without its payload is a slowloris).
        var hb: [9]u8 = undefined;
        readSliceTimed(conn, r, &hb, conn.srv.config.idle_timeout_ms) catch return; // EOF / error / idle -> done
        const fh = parseHeader(&hb);
        if (fh.length > effectiveMaxFrameSize(conn.srv.config)) {
            sendGoaway(conn, .frame_size_error);
            return;
        }
        const payload = gpa.alloc(u8, fh.length) catch return;
        defer gpa.free(payload);
        readSliceTimed(conn, r, payload, conn.srv.config.head_timeout_ms) catch return;

        if (validateInboundFrame(fh, payload)) |code| {
            sendGoaway(conn, code);
            return;
        }

        switch (fh.ftype) {
            .settings => if (!handleSettings(conn, fh, payload)) return,
            .window_update => if (!handleWindowUpdate(conn, fh, payload)) return,
            .ping => {
                if (fh.flags & flag_ack == 0) conn.cw.frame(.ping, flag_ack, 0, payload) catch return;
            },
            .headers => handleHeaders(conn, r, fh, payload) catch return,
            .data => if (!handleData(conn, fh, payload)) return,
            .rst_stream => resetStream(conn, fh.sid),
            .goaway => return, // peer is leaving; stop reading, drain workers
            .priority, .continuation => {}, // stray CONTINUATION ignored; PRIORITY no-op
            else => {},
        }
    }
    sendGoaway(conn, .no_error);
}

/// Returns a connection-error code when `fh`/`payload` violate framing rules
/// (RFC 7540 §4/§6), or null when the frame is structurally acceptable.
fn validateInboundFrame(fh: ParsedHeader, payload: []const u8) ?ErrorCode {
    switch (fh.ftype) {
        .settings => {
            if (fh.sid != 0) return .protocol_error;
            if (fh.flags & flag_ack != 0 and payload.len != 0) return .frame_size_error;
            if (payload.len % 6 != 0) return .frame_size_error;
        },
        .ping => {
            if (fh.sid != 0) return .protocol_error;
            if (payload.len != 8) return .frame_size_error;
        },
        .headers, .data, .priority, .rst_stream, .continuation => {
            if (fh.sid == 0) return .protocol_error;
        },
        .goaway => {
            if (fh.sid != 0) return .protocol_error;
            if (payload.len < 8) return .frame_size_error;
        },
        .window_update => {
            if (payload.len != 4) return .frame_size_error;
        },
        else => {},
    }
    return null;
}

/// Returns false on a connection-fatal SETTINGS (GOAWAY already sent).
fn handleSettings(conn: *Connection, fh: ParsedHeader, payload: []const u8) bool {
    if (fh.flags & flag_ack != 0) return true; // our settings were acked
    var i: usize = 0;
    var new_iw: ?u32 = null;
    while (i + 6 <= payload.len) : (i += 6) {
        const id = std.mem.readInt(u16, payload[i..][0..2], .big);
        const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
        switch (id) {
            set_initial_window_size => {
                // A window over 2^31-1 is a connection FLOW_CONTROL_ERROR
                // (RFC 7540 §6.5.2).
                if (val > 0x7fff_ffff) {
                    sendGoaway(conn, .flow_control_error);
                    return false;
                }
                new_iw = val;
            },
            set_max_frame_size => conn.peer.max_frame_size = val,
            else => {}, // header_table_size/enable_push/max_concurrent_streams: irrelevant to us
        }
    }
    if (new_iw) |iw| applyInitialWindow(conn, iw);
    conn.cw.frame(.settings, flag_ack, 0, "") catch {};
    return true;
}

/// Apply a SETTINGS_INITIAL_WINDOW_SIZE change: shift every live stream's send
/// window by the delta and rebase new-stream initial size (RFC 7540 §6.9.2).
fn applyInitialWindow(conn: *Connection, new_iw: u32) void {
    conn.streams_mu.lockUncancelable(conn.io);
    defer conn.streams_mu.unlock(conn.io);
    const delta: i64 = @as(i64, new_iw) - @as(i64, conn.peer.initial_window_size);
    conn.peer.initial_window_size = new_iw;
    if (delta == 0) return;
    conn.send_mu.lockUncancelable(conn.io);
    var it = conn.streams.valueIterator();
    while (it.next()) |st| st.*.send_window += delta;
    conn.send_cond.broadcast(conn.io);
    conn.send_mu.unlock(conn.io);
}

/// Returns false on a connection-fatal WINDOW_UPDATE (GOAWAY already sent).
fn handleWindowUpdate(conn: *Connection, fh: ParsedHeader, payload: []const u8) bool {
    if (payload.len < 4) return true;
    const incr: i64 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
    // A 0 increment is a PROTOCOL_ERROR: connection-level -> GOAWAY, stream-level
    // -> RST_STREAM (RFC 7540 §6.9).
    if (incr == 0) {
        if (fh.sid == 0) {
            sendGoaway(conn, .protocol_error);
            return false;
        }
        rstStreamCode(conn, fh.sid, .protocol_error);
        return true;
    }
    conn.streams_mu.lockUncancelable(conn.io);
    defer conn.streams_mu.unlock(conn.io);
    conn.send_mu.lockUncancelable(conn.io);
    defer conn.send_mu.unlock(conn.io);
    // The flow-control window must not exceed 2^31-1 (RFC 7540 §6.9.1):
    // connection overflow is fatal; stream overflow resets just that stream.
    // sendGoaway/rstStreamCode only write frames (no lock), so calling them
    // while holding these locks is safe.
    if (fh.sid == 0) {
        if (conn.send_window + incr > 0x7fff_ffff) {
            sendGoaway(conn, .flow_control_error);
            return false;
        }
        conn.send_window += incr;
    } else if (conn.streams.get(fh.sid)) |st| {
        if (st.send_window + incr > 0x7fff_ffff) {
            st.reset.store(true, .release);
            conn.send_cond.broadcast(conn.io);
            rstStreamCode(conn, fh.sid, .flow_control_error);
            return true;
        }
        st.send_window += incr;
    }
    conn.send_cond.broadcast(conn.io);
    return true;
}

/// Max unconsumed request-body bytes buffered per stream before we reset it
/// (bounds memory when a client outruns the handler draining `body_reader`).
const max_request_body: usize = 8 * 1024 * 1024;

/// Hard cap on one request's accumulated header block across HEADERS +
/// CONTINUATION frames; past it the connection gets GOAWAY ENHANCE_YOUR_CALM.
const max_header_block_bytes: usize = 256 * 1024;

/// Returns false on a connection-fatal framing error (GOAWAY already sent).
fn handleData(conn: *Connection, fh: ParsedHeader, payload: []const u8) bool {
    if (fh.sid == 0) return true;
    const end_stream = fh.flags & flag_end_stream != 0;

    // Strip the PADDED prefix: pad-length byte + trailing padding are framing,
    // not body — forwarding them corrupts the request body (RFC 9113 §6.1;
    // pad length >= remaining payload is a connection PROTOCOL_ERROR).
    var data = payload;
    if (fh.flags & flag_padded != 0) {
        if (data.len == 0) {
            sendGoaway(conn, .protocol_error);
            return false;
        }
        const pad = data[0];
        data = data[1..];
        if (pad > data.len) {
            sendGoaway(conn, .protocol_error);
            return false;
        }
        data = data[0 .. data.len - pad];
    }

    // Replenish flow-control windows for what we received. Padding counts
    // toward flow control, so replenish the full frame length.
    if (payload.len > 0) {
        const amt: u31 = @intCast(@min(payload.len, std.math.maxInt(u31)));
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, @as(u32, amt), .big);
        conn.cw.frame(.window_update, 0, 0, &wu) catch {}; // connection-level
        conn.streams_mu.lockUncancelable(conn.io);
        const open = conn.streams.contains(fh.sid);
        conn.streams_mu.unlock(conn.io);
        if (open) conn.cw.frame(.window_update, 0, fh.sid, &wu) catch {};
    }

    // Deliver request DATA to the stream's worker via its rx channel. Every
    // stream runs a worker (spawned at HEADERS) that reads the body through
    // `ctx.body_reader`, so there is one body path for all requests. Hold
    // streams_mu across the whole delivery so the worker (which takes
    // streams_mu in removeStream before freeing the stream) cannot free `s`
    // out from under us. Lock order matches wakeReceivers/resetStream:
    // streams_mu -> rx_mu.
    conn.streams_mu.lockUncancelable(conn.io);
    const s = conn.streams.get(fh.sid) orelse {
        conn.streams_mu.unlock(conn.io);
        return true;
    };
    s.rx_mu.lockUncancelable(conn.io);
    // Bound unconsumed buffering: if the client outruns the handler draining
    // body_reader past our cap, reset the stream instead of growing rx_buf.
    const buffered = s.rx_buf.items.len - s.rx_off;
    if (data.len > 0 and buffered + data.len > max_request_body) {
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
    s.rx_cond.broadcast(conn.io);
    s.rx_mu.unlock(conn.io);
    conn.streams_mu.unlock(conn.io);
    return true;
}

fn resetStream(conn: *Connection, sid: u31) void {
    conn.streams_mu.lockUncancelable(conn.io);
    if (conn.streams.get(sid)) |st| {
        st.reset.store(true, .release);
        // Wake a streaming worker blocked reading request DATA.
        st.rx_mu.lockUncancelable(conn.io);
        st.rx_cond.broadcast(conn.io);
        st.rx_mu.unlock(conn.io);
    }
    conn.streams_mu.unlock(conn.io);
    conn.wakeSenders();
}

fn sendGoaway(conn: *Connection, code: ErrorCode) void {
    var p: [8]u8 = undefined;
    std.mem.writeInt(u32, p[0..4], @as(u32, conn.last_stream_id), .big);
    std.mem.writeInt(u32, p[4..8], @intFromEnum(code), .big);
    conn.cw.frame(.goaway, 0, 0, &p) catch {};
}

/// Reads a (possibly CONTINUATION-extended) header block, decodes it, builds a
/// Request, and spawns a worker. Returns error only on fatal transport failure.
fn handleHeaders(conn: *Connection, r: *Io.Reader, fh: ParsedHeader, first: []const u8) !void {
    const gpa = conn.gpa;

    // Strip PADDED / PRIORITY prefixes from the first fragment.
    var frag = first;
    if (fh.flags & flag_padded != 0) {
        if (frag.len == 0) return;
        const pad = frag[0];
        frag = frag[1..];
        if (pad > frag.len) return;
        frag = frag[0 .. frag.len - pad];
    }
    if (fh.flags & flag_priority != 0) {
        if (frag.len < 5) return;
        frag = frag[5..];
    }

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, frag);

    // Pull CONTINUATION frames until END_HEADERS (no interleaving permitted).
    // The accumulated block is hard-capped: an attacker streaming CONTINUATION
    // frames forever must not grow `block` without bound (CVE-2024-27316 class).
    if (fh.flags & flag_end_headers == 0) {
        while (true) {
            var hb: [9]u8 = undefined;
            try readSliceTimed(conn, r, &hb, conn.srv.config.head_timeout_ms);
            const cf = parseHeader(&hb);
            if (cf.ftype != .continuation or cf.sid != fh.sid or cf.length > effectiveMaxFrameSize(conn.srv.config)) return error.ProtocolError;
            if (block.items.len + cf.length > max_header_block_bytes) {
                sendGoaway(conn, .enhance_your_calm);
                return error.ProtocolError;
            }
            const cp = try gpa.alloc(u8, cf.length);
            defer gpa.free(cp);
            try readSliceTimed(conn, r, cp, conn.srv.config.head_timeout_ms);
            try block.appendSlice(gpa, cp);
            if (cf.flags & flag_end_headers != 0) break;
        }
    }

    // New stream id must be odd and strictly increasing.
    if (fh.sid <= conn.last_stream_id or fh.sid % 2 == 0) {
        sendGoaway(conn, .protocol_error);
        return error.ProtocolError;
    }
    conn.last_stream_id = fh.sid;

    // Graceful shutdown: stop accepting new streams once the server is stopping.
    // Refuse this one; in-flight streams keep draining and readLoop sends the
    // connection GOAWAY when it exits.
    if (conn.srv.stop.load(.acquire)) {
        rstStreamCode(conn, fh.sid, .refused_stream);
        return;
    }

    // Concurrency cap.
    conn.streams_mu.lockUncancelable(conn.io);
    const count = conn.streams.count();
    conn.streams_mu.unlock(conn.io);
    if (count >= conn.srv.config.max_concurrent_streams) {
        rstStreamCode(conn, fh.sid, .refused_stream);
        return;
    }

    // Build the stream (owns its request arena). Decode happens on this (reader)
    // thread so the HPACK decoder stays single-threaded.
    const st = gpa.create(H2Stream) catch return;
    st.* = .{
        .conn = conn,
        .id = fh.sid,
        .arena_state = std.heap.ArenaAllocator.init(gpa),
        .req = undefined,
        .send_window = conn.peer.initial_window_size,
    };
    const arena = st.arena();
    const decoded = conn.decoder.decode(arena, block.items) catch {
        st.arena_state.deinit();
        gpa.destroy(st);
        sendGoaway(conn, .protocol_error);
        return error.ProtocolError;
    };
    st.req = buildRequest(arena, decoded) catch |err| {
        st.arena_state.deinit();
        gpa.destroy(st);
        if (err == error.BadRequest) {
            rstStreamCode(conn, fh.sid, .protocol_error);
            return;
        }
        return;
    };

    conn.streams_mu.lockUncancelable(conn.io);
    conn.streams.put(gpa, fh.sid, st) catch {
        conn.streams_mu.unlock(conn.io);
        st.arena_state.deinit();
        gpa.destroy(st);
        return;
    };
    conn.streams_mu.unlock(conn.io);

    // Dispatch the worker as soon as headers decode. The request body (if any)
    // streams to the handler through `ctx.body_reader`; a bodyless request
    // (END_STREAM on HEADERS) has no DATA coming, so preset rx EOF and the
    // reader returns 0 immediately. Setting these here is race-free: the worker
    // has not been spawned yet, so this thread owns `st`.
    if (fh.flags & flag_end_stream != 0) st.rx_eof = true else st.has_body = true;
    spawnWorker(conn, st);
}

/// Registers worker accounting and spawns the per-stream worker thread.
fn spawnWorker(conn: *Connection, st: *H2Stream) void {
    conn.workers_mu.lockUncancelable(conn.io);
    conn.active_workers += 1;
    conn.workers_mu.unlock(conn.io);

    const t = std.Thread.spawn(.{}, runStream, .{st}) catch {
        conn.workers_mu.lockUncancelable(conn.io);
        conn.active_workers -= 1;
        conn.workers_mu.unlock(conn.io);
        removeStream(conn, st.id);
        return;
    };
    t.detach();
}

fn buildRequest(arena: std.mem.Allocator, decoded: []const hpack.Header) !types.Request {
    var method: []const u8 = "";
    var scheme: []const u8 = "";
    var path: []const u8 = "";
    var authority: []const u8 = "";
    var host: ?[]const u8 = null;
    var content_length: ?u64 = null;
    var hdrs: std.ArrayList(types.Header) = .empty;
    var saw_regular = false;

    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;

    for (decoded) |h| {
        if (h.name.len > 0 and h.name[0] == ':') {
            if (saw_regular) return error.BadRequest;
            if (std.mem.eql(u8, h.name, ":method")) {
                if (seen_method) return error.BadRequest;
                seen_method = true;
                method = h.value;
            } else if (std.mem.eql(u8, h.name, ":scheme")) {
                if (seen_scheme) return error.BadRequest;
                seen_scheme = true;
                scheme = h.value;
            } else if (std.mem.eql(u8, h.name, ":path")) {
                if (seen_path) return error.BadRequest;
                seen_path = true;
                path = h.value;
            } else if (std.mem.eql(u8, h.name, ":authority")) {
                if (seen_authority) return error.BadRequest;
                seen_authority = true;
                authority = h.value;
            } else {
                return error.BadRequest;
            }
            continue;
        }
        saw_regular = true;
        if (isConnectionSpecificHeader(h.name)) return error.BadRequest;
        if (std.ascii.eqlIgnoreCase(h.name, "te") and !std.mem.eql(u8, h.value, "trailers")) return error.BadRequest;
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) {
            content_length = std.fmt.parseInt(u64, h.value, 10) catch null;
        }
        if (std.ascii.eqlIgnoreCase(h.name, "host")) {
            host = h.value;
        }
        try hdrs.append(arena, .{ .name = h.name, .value = h.value });
    }
    if (authority.len > 0) {
        if (host) |existing_host| {
            if (!std.ascii.eqlIgnoreCase(existing_host, authority)) return error.BadRequest;
        } else {
            // No explicit host: synthesize one from :authority so callers that
            // route by host (e.g. a CDN's site lookup) work without extra logic.
            try hdrs.append(arena, .{ .name = "host", .value = authority });
        }
    }

    if (!seen_method or method.len == 0) return error.BadRequest;
    if (!seen_scheme or scheme.len == 0) return error.BadRequest;
    if (std.mem.eql(u8, method, "CONNECT")) return error.BadRequest;
    if (!seen_path or path.len == 0) return error.BadRequest;

    return .{
        .method = method,
        .target = path,
        .minor_version = 0,
        .headers = try hdrs.toOwnedSlice(arena),
        .content_length = content_length,
        .keep_alive = true,
    };
}

fn runStream(st: *H2Stream) void {
    const conn = st.conn;
    defer {
        // Stop the deadline watchdog first and reap it before freeing `st`.
        st.done.store(true, .release);
        if (st.deadline_thread) |w| w.join();
        removeStream(conn, st.id);
        st.rx_buf.deinit(conn.gpa);
        st.arena_state.deinit();
        conn.gpa.destroy(st);
        conn.workers_mu.lockUncancelable(conn.io);
        conn.active_workers -= 1;
        conn.workers_cond.signal(conn.io);
        conn.workers_mu.unlock(conn.io);
    }

    var h2: H2Sink = .{ .stream = st };
    var res: types.Response = .{
        .arena = st.arena(),
        .sink = h2.sink(),
        .minor_version = 0,
    };
    var ctx: types.Context = .{
        .req = &st.req,
        .res = &res,
        .arena = st.arena(),
        .io = conn.io,
        .userdata = conn.srv.userdata,
        .body_reader = st.bodyReader(),
        .has_body = st.has_body,
        .client_ip = conn.client_ip,
        .scheme = conn.scheme,
        .set_deadline_ctx = st,
        .set_deadline_fn = h2SetDeadline,
    };

    conn.srv.handler(&ctx) catch |err| {
        // A handler that fails mid-response (HEADERS already sent) can't be
        // salvaged with a clean error response, so RST_STREAM the stream in
        // either case. Skipping the RST when the head is already out leaves the
        // client blocked forever waiting for an END_STREAM that never arrives.
        if (st.reset.load(.acquire) or conn.closing.load(.acquire)) return;
        log.warn("h2 handler error: {t}", .{err});
        rstStreamCode(conn, st.id, .internal_error);
        return;
    };
    // Normal completion: ensure the response head + END_STREAM are emitted.
    if (st.reset.load(.acquire) or conn.closing.load(.acquire)) return;
    res.finish() catch {};
}

fn removeStream(conn: *Connection, sid: u31) void {
    conn.streams_mu.lockUncancelable(conn.io);
    _ = conn.streams.remove(sid);
    conn.streams_mu.unlock(conn.io);
}

fn rstStreamCode(conn: *Connection, sid: u31, code: ErrorCode) void {
    var p: [4]u8 = undefined;
    std.mem.writeInt(u32, &p, @intFromEnum(code), .big);
    conn.cw.frame(.rst_stream, 0, sid, &p) catch {};
}

fn isConnectionSpecificHeader(name: []const u8) bool {
    const banned = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (banned) |b| {
        if (std.ascii.eqlIgnoreCase(name, b)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests. Transport-level tests talk raw h2 frames over a plain AF_UNIX
// socketpair — no TLS — so the suite is self-contained and dependency-free.
// ---------------------------------------------------------------------------

const testing = std.testing;

const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("unistd.h");
});

test "buildResponseHeaders injects content-length for known-size responses" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var res: types.Response = .{
        .arena = arena,
        .sink = undefined,
    };
    try res.header("content-type", "text/plain");
    res.setContentLength(12);

    const hdrs = try buildResponseHeaders(&res);

    try testing.expectEqual(@as(usize, 2), hdrs.len);
    try testing.expectEqualStrings("text/plain", findHeaderValue(hdrs, "content-type").?);
    try testing.expectEqualStrings("12", findHeaderValue(hdrs, "content-length").?);
}

test "buildResponseHeaders keeps explicit content-length" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var res: types.Response = .{
        .arena = arena,
        .sink = undefined,
    };
    try res.header("content-length", "99");
    res.setContentLength(12);

    const hdrs = try buildResponseHeaders(&res);

    try testing.expectEqual(@as(usize, 1), hdrs.len);
    try testing.expectEqualStrings("99", findHeaderValue(hdrs, "content-length").?);
}

fn findHeaderValue(headers: []const hpack.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

test "buildRequest reuses explicit host when it matches authority" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "host", .value = "example.com" },
    };

    const req = try buildRequest(arena, &decoded);

    try testing.expectEqualStrings("example.com", req.get("host").?);
    try testing.expectEqual(@as(usize, 1), countHeaders(req.headers, "host"));
}

test "buildRequest rejects conflicting host and authority" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/asset" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "host", .value = "other.example.com" },
    };

    try testing.expectError(error.BadRequest, buildRequest(arena, &decoded));
}

fn countHeaders(headers: []const types.Header, name: []const u8) usize {
    var count: usize = 0;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) count += 1;
    }
    return count;
}

test "validateInboundFrame rejects SETTINGS ack with payload" {
    try testing.expectEqual(
        @as(?ErrorCode, .frame_size_error),
        validateInboundFrame(.{ .length = 6, .ftype = .settings, .flags = flag_ack, .sid = 0 }, &[_]u8{ 0, 1, 0, 0, 0, 1 }),
    );
}

test "validateInboundFrame rejects PING on stream" {
    try testing.expectEqual(
        @as(?ErrorCode, .protocol_error),
        validateInboundFrame(.{ .length = 8, .ftype = .ping, .flags = 0, .sid = 1 }, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }),
    );
}

test "validateInboundFrame rejects HEADERS on stream 0" {
    try testing.expectEqual(
        @as(?ErrorCode, .protocol_error),
        validateInboundFrame(.{ .length = 0, .ftype = .headers, .flags = flag_end_headers, .sid = 0 }, &[_]u8{}),
    );
}

test "validateInboundFrame rejects short GOAWAY" {
    try testing.expectEqual(
        @as(?ErrorCode, .frame_size_error),
        validateInboundFrame(.{ .length = 4, .ftype = .goaway, .flags = 0, .sid = 0 }, &[_]u8{ 0, 0, 0, 0 }),
    );
}

test "validateInboundFrame accepts normal client SETTINGS" {
    const payload = [_]u8{ 0, 4, 0, 0, 0xff, 0xff };
    try testing.expectEqual(
        @as(?ErrorCode, null),
        validateInboundFrame(.{ .length = payload.len, .ftype = .settings, .flags = 0, .sid = 0 }, &payload),
    );
}

test "buildRequest rejects pseudo header after regular header" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":path", .value = "/late" },
        .{ .name = ":scheme", .value = "https" },
    };

    try testing.expectError(error.BadRequest, buildRequest(arena, &decoded));
}

test "buildRequest rejects duplicate pseudo headers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/dup" },
    };

    try testing.expectError(error.BadRequest, buildRequest(arena, &decoded));
}

test "buildRequest rejects connection-specific headers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = "connection", .value = "keep-alive" },
    };

    try testing.expectError(error.BadRequest, buildRequest(arena, &decoded));
}

test "buildRequest rejects te other than trailers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = "te", .value = "gzip" },
    };

    try testing.expectError(error.BadRequest, buildRequest(arena, &decoded));
}

test "buildRequest requires scheme and path" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
    };

    try testing.expectError(error.BadRequest, buildRequest(arena, &decoded));
}

// --- raw-frame transport test helpers ---------------------------------------

const h2_test_body = "Hello plain HTTP/2";

fn h2TestHandler(ctx: *types.Context) anyerror!void {
    try ctx.res.send(200, "text/plain", h2_test_body);
}

fn h2EchoHandler(ctx: *types.Context) anyerror!void {
    var buf: [256]u8 = undefined;
    var total: usize = 0;
    if (ctx.body_reader) |br| {
        while (total < buf.len) {
            const n = try br.read(buf[total..]);
            if (n == 0) break;
            total += n;
        }
    }
    try ctx.res.send(200, "application/octet-stream", buf[0..total]);
}

/// Emits a response head + partial body, then fails — exercises the
/// "handler error after HEADERS sent" path. The driver must RST the stream so
/// the client isn't left waiting for END_STREAM.
fn h2PartialFailHandler(ctx: *types.Context) anyerror!void {
    ctx.res.status(200);
    try ctx.res.header("content-type", "text/plain");
    try ctx.res.write("partial"); // forces HEADERS + DATA out; head_sent = true
    return error.SimulatedHandlerFailure;
}

var saw_deadline = std.atomic.Value(bool).init(false);

/// Arms a short deadline then blocks reading the request body; the deadline
/// watchdog must abort the read with DeadlineExceeded.
fn deadlineReadHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(60 * std.time.ns_per_ms);
    if (ctx.body_reader) |br| {
        var tmp: [64]u8 = undefined;
        while (true) {
            const n = br.read(&tmp) catch |err| switch (err) {
                error.DeadlineExceeded => {
                    saw_deadline.store(true, .release);
                    return err;
                },
                else => return err,
            };
            if (n == 0) break;
        }
    }
    return error.TestUnexpectedResult;
}

/// Wraps `fd` as a stream and drives one h2 connection over it (plain, no TLS).
fn serveRawH2OnFd(srv: *Server, fd: std.posix.fd_t) void {
    defer _ = c.close(fd);

    const stream: net.Stream = .{ .socket = .{
        .handle = fd,
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(srv.io, &rbuf);
    var sw = stream.writer(srv.io, &wbuf);
    serveConn(srv, &sr.interface, &sw.interface, null, "https");
}

const TestFrame = struct {
    header: ParsedHeader,
    payload: []u8,

    fn deinit(self: *TestFrame, alloc: std.mem.Allocator) void {
        alloc.free(self.payload);
    }
};

fn readFrameAlloc(alloc: std.mem.Allocator, r: *Io.Reader) !TestFrame {
    var hb: [9]u8 = undefined;
    try r.readSliceAll(&hb);
    const header = parseHeader(&hb);
    const payload = try alloc.alloc(u8, header.length);
    errdefer alloc.free(payload);
    if (payload.len > 0) try r.readSliceAll(payload);
    return .{ .header = header, .payload = payload };
}

fn writeFrame(w: *Io.Writer, ftype: FrameType, flags: u8, sid: u31, payload: []const u8) !void {
    var hb: [9]u8 = undefined;
    putHeader(&hb, payload.len, ftype, flags, sid);
    try w.writeAll(&hb);
    if (payload.len > 0) try w.writeAll(payload);
    try w.flush();
}

/// Reads frames, skipping any that are not of type `want` (settings acks,
/// window updates, ...). Caller frees the returned frame's payload.
fn readFrameOfType(alloc: std.mem.Allocator, r: *Io.Reader, want: FrameType) !TestFrame {
    while (true) {
        var f = try readFrameAlloc(alloc, r);
        if (f.header.ftype == want) return f;
        f.deinit(alloc);
    }
}

fn newSocketPair() ![2]c_int {
    var fds: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    return fds;
}

fn peerStream(fd: std.posix.fd_t) net.Stream {
    return .{ .socket = .{
        .handle = fd,
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
}

test "http2 raw frame round trip" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    // Shutdown is LIFO: close the client end first so the server's read loop
    // sees EOF and exits, then join. In the reverse order join blocks for the
    // full idle_timeout_ms (180s) waiting on a server that will never read
    // another frame, since the client only closes after join.
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();

    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    defer settings.deinit(testing.allocator);
    try testing.expectEqual(FrameType.settings, settings.header.ftype);
    try testing.expectEqual(@as(u31, 0), settings.header.sid);

    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");

    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);

    var ack = try readFrameAlloc(testing.allocator, &reader.interface);
    defer ack.deinit(testing.allocator);
    try testing.expectEqual(FrameType.settings, ack.header.ftype);
    try testing.expectEqual(flag_ack, ack.header.flags);

    var resp = try readFrameAlloc(testing.allocator, &reader.interface);
    defer resp.deinit(testing.allocator);
    try testing.expectEqual(FrameType.headers, resp.header.ftype);
    try testing.expectEqual(@as(u31, 1), resp.header.sid);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var dec = hpack.Decoder.init(testing.allocator, our_header_table_size);
    defer dec.deinit();
    const headers = try dec.decode(arena, resp.payload);
    try testing.expectEqualStrings("200", findHeaderValue(headers, ":status").?);
    try testing.expectEqualStrings("text/plain", findHeaderValue(headers, "content-type").?);
    try testing.expectEqualStrings("18", findHeaderValue(headers, "content-length").?);

    var data = try readFrameAlloc(testing.allocator, &reader.interface);
    defer data.deinit(testing.allocator);
    try testing.expectEqual(FrameType.data, data.header.ftype);
    try testing.expectEqual(@as(u31, 1), data.header.sid);
    try testing.expectEqualStrings(h2_test_body, data.payload);
    try testing.expectEqual(@as(u8, 0), data.header.flags & flag_end_stream);

    var end = try readFrameAlloc(testing.allocator, &reader.interface);
    defer end.deinit(testing.allocator);
    try testing.expectEqual(FrameType.data, end.header.ftype);
    try testing.expectEqual(@as(u32, 0), end.header.length);
    try testing.expectEqual(flag_end_stream, end.header.flags & flag_end_stream);
}

test "h2: handler failure after a partial response RSTs the stream" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2PartialFailHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    // Shutdown is LIFO: close the client end first so the server's read loop
    // sees EOF and exits, then join.
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();

    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    defer settings.deinit(testing.allocator);
    try testing.expectEqual(FrameType.settings, settings.header.ftype);

    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");

    // GET / (bodyless): the handler emits HEADERS + a partial DATA frame, then
    // returns an error.
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);

    // Skip the partial HEADERS/DATA; the handler error must surface as a
    // RST_STREAM (internal_error) on stream 1.
    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(usize, 4), rst.payload.len);
    try testing.expectEqual(@intFromEnum(ErrorCode.internal_error), std.mem.readInt(u32, rst.payload[0..4], .big));
}

test "h2: padded DATA delivers the un-padded body (B-5)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2EchoHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    // Shutdown is LIFO: close the client end first so the server's read loop
    // sees EOF and exits, then join. In the reverse order join blocks for the
    // full idle_timeout_ms (180s) waiting on a server that will never read
    // another frame, since the client only closes after join.
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    try writeFrame(&writer.interface, .settings, 0, 0, "");

    // POST / with a body: :method POST (idx 3), :scheme http, :path /, authority.
    const req_block = [_]u8{
        0x83, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);

    // DATA with PADDED: [pad_len=3]["hello"][3 pad bytes]. The handler must
    // see exactly "hello".
    const padded = [_]u8{3} ++ "hello".* ++ [_]u8{ 0, 0, 0 };
    try writeFrame(&writer.interface, .data, flag_padded | flag_end_stream, 1, &padded);

    var resp = try readFrameOfType(testing.allocator, &reader.interface, .headers);
    defer resp.deinit(testing.allocator);
    var data = try readFrameOfType(testing.allocator, &reader.interface, .data);
    defer data.deinit(testing.allocator);
    try testing.expectEqualStrings("hello", data.payload);
}

test "h2: CONTINUATION flood is capped with GOAWAY ENHANCE_YOUR_CALM (B-4)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    // Shutdown is LIFO: close the client end first so the server's read loop
    // sees EOF and exits, then join. In the reverse order join blocks for the
    // full idle_timeout_ms (180s) waiting on a server that will never read
    // another frame, since the client only closes after join.
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    try writeFrame(&writer.interface, .settings, 0, 0, "");

    // HEADERS without END_HEADERS, then an endless CONTINUATION stream. The
    // server must cut the connection once the accumulated block passes the cap
    // instead of buffering forever.
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, 0, 1, &req_block);
    var junk: [4096]u8 = undefined;
    @memset(&junk, 0x00);
    // 256KiB cap / 4KiB per frame = 64 frames; send extra. Writes may start
    // failing once the server closes — that already proves the cut-off.
    var sent: usize = 0;
    while (sent < 80) : (sent += 1) {
        writeFrame(&writer.interface, .continuation, 0, 1, &junk) catch break;
    }

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expect(goaway.payload.len >= 8);
    const code = std.mem.readInt(u32, goaway.payload[4..8], .big);
    try testing.expectEqual(@intFromEnum(ErrorCode.enhance_your_calm), code);
}

test "h2: SETTINGS_INITIAL_WINDOW_SIZE over 2^31-1 is a connection FLOW_CONTROL_ERROR (B-9)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    // Shutdown is LIFO: close the client end first so the server's read loop
    // sees EOF and exits, then join. In the reverse order join blocks for the
    // full idle_timeout_ms (180s) waiting on a server that will never read
    // another frame, since the client only closes after join.
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    // SETTINGS with SETTINGS_INITIAL_WINDOW_SIZE = 0x80000000 (over the max).
    var s: [6]u8 = undefined;
    std.mem.writeInt(u16, s[0..2], set_initial_window_size, .big);
    std.mem.writeInt(u32, s[2..6], 0x8000_0000, .big);
    try writeFrame(&writer.interface, .settings, 0, 0, &s);

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expect(goaway.payload.len >= 8);
    try testing.expectEqual(@intFromEnum(ErrorCode.flow_control_error), std.mem.readInt(u32, goaway.payload[4..8], .big));
}

// A gRPC-style handler: echoes the (already framed) request body and closes with
// a grpc-status trailer. Exercises request-body streaming (via body_reader) +
// trailer emission.
fn grpcEchoHandler(ctx: *types.Context) anyerror!void {
    const res = ctx.res;
    res.status(200);
    try res.header("content-type", "application/grpc");
    if (ctx.body_reader) |br| {
        var tmp: [1024]u8 = undefined;
        while (true) {
            const n = try br.read(&tmp);
            if (n == 0) break;
            try res.write(tmp[0..n]);
        }
    }
    try res.trailer("grpc-status", "0");
    try res.finish();
}

test "http2 client: gRPC unary echo against the real server (plain transport)" {
    const client_mod = @import("client.zig");

    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = grpcEchoHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    // Shutdown is LIFO: close the client end first so the server's read loop
    // sees EOF and exits, then join. In the reverse order join blocks for the
    // full idle_timeout_ms (180s) waiting on a server that will never read
    // another frame, since the client only closes after join.
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    var client: client_mod.Client = undefined;
    try client.init(testing.io, testing.allocator, &reader.interface, &writer.interface);
    defer client.deinit();

    const req_headers = [_]hpack.Header{
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };
    const cstream = try client.openStream(.{ .path = "/svc.Test/Echo", .headers = &req_headers }, false);
    const framed_ping = [_]u8{ 0, 0, 0, 0, 4, 'p', 'i', 'n', 'g' };
    try cstream.send(&framed_ping, true);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var got_status: ?[]const u8 = null;
    var got_data: ?[]const u8 = null;
    var got_grpc_status: ?[]const u8 = null;
    var done = false;
    var iters: usize = 0;
    while (!done and iters < 16) : (iters += 1) {
        switch (try cstream.readEvent(arena)) {
            .headers => |h| {
                if (findHeaderValue(h.headers, ":status")) |s| got_status = s;
                if (findHeaderValue(h.headers, "grpc-status")) |s| got_grpc_status = s;
                if (h.end_stream) done = true;
            },
            .data => |d| {
                got_data = d.payload;
                if (d.end_stream) done = true;
            },
            .rst, .goaway => return error.UnexpectedStreamEnd,
        }
    }
    try testing.expectEqualStrings("200", got_status.?);
    try testing.expectEqualStrings(&framed_ping, got_data.?);
    try testing.expectEqualStrings("0", got_grpc_status.?);
}

test "h2 client: close() reclaims finished streams (no leak)" {
    const client_mod = @import("client.zig");

    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        .config = .{},
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

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Open several streams, drain each to end-of-stream, then close() it.
    var n: usize = 0;
    while (n < 5) : (n += 1) {
        const s = try client.openStream(.{ .path = "/x", .method = "GET" }, true);
        drain: while (true) {
            const ev = s.readEvent(arena) catch |e| switch (e) {
                error.EndOfStream => break :drain,
                else => return e,
            };
            switch (ev) {
                .data => |d| if (d.end_stream) break :drain,
                .headers => |h| if (h.end_stream) break :drain,
                .rst, .goaway => return error.UnexpectedStreamEnd,
            }
        }
        s.close();
    }

    // Every opened stream was close()d, so none must linger in the registry.
    // Before the fix, finished streams were only reclaimed at Client.deinit.
    client.streams_mu.lockUncancelable(testing.io);
    const remaining = client.streams.count();
    client.streams_mu.unlock(testing.io);
    try testing.expectEqual(@as(usize, 0), remaining);
}

test "h2: response finish() is idempotent (exactly one END_STREAM trailer)" {
    // grpcEchoHandler sets a trailer and calls finish() itself; runStream then
    // calls finish() again. finish() must be idempotent — a duplicate END_STREAM
    // (a second trailers HEADERS) is a stream/protocol error. Sending GOAWAY
    // right after the request makes the server drain the worker (so every
    // response frame is written) and then close, giving the reader a clean EOF.
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = grpcEchoHandler,
        .config = .{},
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
    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    defer settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);
    try writeFrame(&writer.interface, .goaway, 0, 0, &[_]u8{0} ** 8);

    var end_stream: usize = 0;
    while (true) {
        var f = readFrameAlloc(testing.allocator, &reader.interface) catch break; // EOF when server closes
        defer f.deinit(testing.allocator);
        // flag_end_stream (0x1) collides with flag_ack on SETTINGS; only
        // HEADERS/DATA may carry END_STREAM, so restrict the count to those.
        switch (f.header.ftype) {
            .headers, .data => if (f.header.flags & flag_end_stream != 0) {
                end_stream += 1;
            },
            else => {},
        }
    }
    try testing.expectEqual(@as(usize, 1), end_stream);
}

test "h2: server advertises configured SETTINGS" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        .config = .{ .max_concurrent_streams = 7, .max_frame_size = 65536, .initial_window_size = 131072 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var wbuf: [128]u8 = undefined;
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();

    var rbuf: [256]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var s = try readFrameAlloc(testing.allocator, &reader.interface);
    defer s.deinit(testing.allocator);
    try testing.expectEqual(FrameType.settings, s.header.ftype);

    var max_concurrent: ?u32 = null;
    var max_frame: ?u32 = null;
    var init_window: ?u32 = null;
    var i: usize = 0;
    while (i + 6 <= s.payload.len) : (i += 6) {
        const id = std.mem.readInt(u16, s.payload[i..][0..2], .big);
        const val = std.mem.readInt(u32, s.payload[i + 2 ..][0..4], .big);
        switch (id) {
            set_max_concurrent_streams => max_concurrent = val,
            set_max_frame_size => max_frame = val,
            set_initial_window_size => init_window = val,
            else => {},
        }
    }
    try testing.expectEqual(@as(u32, 7), max_concurrent.?);
    try testing.expectEqual(@as(u32, 65536), max_frame.?);
    try testing.expectEqual(@as(u32, 131072), init_window.?);
}

test "h2 client: cancel() sends RST_STREAM(CANCEL) on the stream" {
    const client_mod = @import("client.zig");
    const fds = try newSocketPair();
    defer {
        _ = c.close(fds[0]);
        _ = c.close(fds[1]);
    }

    // Client writes on fds[1]; we read its raw output on fds[0].
    var crbuf: [256]u8 = undefined;
    var cwbuf: [256]u8 = undefined;
    var cr = peerStream(fds[1]).reader(testing.io, &crbuf);
    var cw = peerStream(fds[1]).writer(testing.io, &cwbuf);
    var client: client_mod.Client = undefined;
    try client.init(testing.io, testing.allocator, &cr.interface, &cw.interface);
    defer client.deinit();
    const cstream = try client.openStream(.{ .path = "/svc/X/Y" }, false);
    try cstream.cancel();

    var srbuf: [256]u8 = undefined;
    var sr = peerStream(fds[0]).reader(testing.io, &srbuf);
    var pre: [preface.len]u8 = undefined;
    try sr.interface.readSliceAll(&pre); // skip client connection preface
    var rst = try readFrameOfType(testing.allocator, &sr.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(usize, 4), rst.payload.len);
    try testing.expectEqual(@intFromEnum(ErrorCode.cancel), std.mem.readInt(u32, rst.payload[0..4], .big));
}

test "h2: per-RPC deadline aborts a blocked body read" {
    saw_deadline.store(false, .release);
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = deadlineReadHandler,
        .config = .{},
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
    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    defer settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    // No END_STREAM → the handler blocks on body_reader until the deadline fires.
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);

    // Deadline is 60ms; wait past it for the watchdog to abort the read.
    Io.sleep(testing.io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(saw_deadline.load(.acquire));
}

test "h2 client: multiplexes concurrent streams over one connection" {
    const client_mod = @import("client.zig");
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2EchoHandler,
        .config = .{},
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
    defer client.deinit(); // must stop the client reader before fds[1] closes

    const N = 4;
    const Worker = struct {
        fn run(cli: *client_mod.Client, idx: usize, ok: *std.atomic.Value(u32)) void {
            var body_buf: [40]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "hello from stream {d}", .{idx}) catch return;
            const s = cli.openStream(.{ .path = "/echo", .method = "POST" }, false) catch return;
            s.send(body, true) catch return;
            var arena_state = std.heap.ArenaAllocator.init(cli.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var got = std.ArrayList(u8).empty;
            defer got.deinit(cli.gpa);
            while (true) {
                const ev = s.readEvent(arena) catch return;
                switch (ev) {
                    .data => |d| {
                        got.appendSlice(cli.gpa, d.payload) catch return;
                        if (d.end_stream) break;
                    },
                    .headers => |h| if (h.end_stream) {
                        break;
                    },
                    .rst, .goaway => return,
                }
            }
            if (std.mem.eql(u8, got.items, body)) _ = ok.fetchAdd(1, .acq_rel);
        }
    };

    var success = std.atomic.Value(u32).init(0);
    var threads: [N]std.Thread = undefined;
    for (0..N) |i| threads[i] = std.Thread.spawn(.{}, Worker.run, .{ &client, i, &success }) catch return;
    for (threads) |th| th.join();
    try testing.expectEqual(@as(u32, N), success.load(.acquire));
}