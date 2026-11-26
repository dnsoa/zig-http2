//! HTTP/2 server (RFC 9113) over an already-established transport, reached when
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
const set_max_header_list_size = proto2.set_max_header_list_size;
const our_max_frame_size = proto2.our_max_frame_size;
const our_header_table_size = proto2.our_header_table_size;
const default_window = proto2.default_window;
const clampConnWindow = proto2.clampConnWindow;
const clampInitialWindow = proto2.clampInitialWindow;
const ParsedHeader = proto2.ParsedHeader;
const putHeader = proto2.putHeader;
const parseHeader = proto2.parseHeader;
const putSetting = proto2.putSetting;

// Server-only limit (not shared).
const our_max_concurrent: u32 = 128;

const Settings = struct {
    /// Peer's SETTINGS_INITIAL_WINDOW_SIZE. Reader-thread-only (read in
    /// handleHeaders, written in applyInitialWindow), so a plain field.
    initial_window_size: u32 = 65535,
    /// Peer's most recent SETTINGS_HEADER_TABLE_SIZE (reader-thread-only).
    header_table_size: u32 = our_header_table_size,
    /// Peer's SETTINGS_MAX_FRAME_SIZE. Written by the reader thread on SETTINGS
    /// and read by worker threads sizing DATA/HEADERS frames, so it is atomic
    /// rather than a plain field shared across threads.
    max_frame_size: std.atomic.Value(u32) = .init(16384),
};

/// Timeouts and limits for a server connection.
pub const Config = struct {
    /// Bound on reading one request head / h2 frame payload once bytes are
    /// expected (anti-slowloris). 0 = unbounded.
    head_timeout_ms: u64 = 30_000,
    /// Keep-alive: max idle wait for the next frame header before the connection
    /// is closed. 0 = unbounded.
    idle_timeout_ms: u64 = 180_000,
    /// Optional deadline (ms, anchored when graceful drain begins) after which
    /// the drain read loop stops and flips `closing`, aborting any blocked
    /// stream I/O (`body_reader.read` / response writes) before awaiting
    /// handler task exit. Pure CPU/sleep handlers that touch no stream I/O
    /// still run until they return. When 0, bodyless handlers are unbounded
    /// while peer-stalled streams remain bounded by head/idle timeouts.
    drain_timeout_ms: u64 = 0,
    /// Max concurrent streams we serve — advertised as
    /// SETTINGS_MAX_CONCURRENT_STREAMS and enforced on inbound HEADERS.
    max_concurrent_streams: u32 = our_max_concurrent,
    /// SETTINGS_MAX_FRAME_SIZE we advertise and enforce inbound (clamped to the
    /// RFC range 16384..16777215). Larger frames cut per-message overhead.
    max_frame_size: u32 = our_max_frame_size,
    /// SETTINGS_INITIAL_WINDOW_SIZE we advertise for stream-level flow control
    /// on DATA we receive — the peer's initial send window into us (0..2^31-1).
    /// NOTE: values below 65535 can cause a spec-compliant client to be reset:
    /// until it processes our SETTINGS it uses the RFC default 65535-byte stream
    /// window and may overshoot the smaller value we advertise. Keep >= 65535
    /// unless clients are known to wait for SETTINGS before sending body DATA.
    initial_window_size: u32 = @intCast(default_window),
    /// Connection-level inbound flow-control window (aggregate across streams).
    /// RFC's fixed initial is 65535; if larger, we enlarge via a stream-0
    /// WINDOW_UPDATE at startup. Clamped to [65535, 2^31-1].
    connection_window_size: u32 = 1 << 20,
    /// Max non-ACK PING, non-ACK SETTINGS (post-preface), PRIORITY, and empty
    /// non-END_STREAM DATA frames allowed within `control_frame_window_ms`
    /// before tearing down with GOAWAY(ENHANCE_YOUR_CALM) (#36). 0 disables.
    max_control_frames_per_window: u32 = 500,
    /// Sliding window duration (ms) for `max_control_frames_per_window`.
    /// When 0 and `max_control_frames_per_window > 0`, acts as a per-connection cap.
    control_frame_window_ms: u64 = 10_000,
    /// Max consecutive empty (0 unpadded body bytes) non-END_STREAM DATA frames
    /// before tearing down with GOAWAY(ENHANCE_YOUR_CALM) (CVE-2019-9518). 0 disables.
    max_empty_data_frames: u32 = 32,
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
    /// REFUSED_STREAM) and idle connections wake promptly (within `stop_poll_ms`)
    /// to emit GOAWAY(NO_ERROR) and drain in-flight workers. Prefer
    /// `requestStop()` outside async signal handlers for immediate wakeup.
    stop: std.atomic.Value(bool) = .init(false),
    /// Signaled by `requestStop()` to wake all idle connections blocked on
    /// `idle_timeout_ms` instantaneously (`Io.Event.set` broadcasts all waiters
    /// and remains set).
    stop_event: Io.Event = .unset,

    /// Requests graceful shutdown: marks `stop = true` and wakes all idle
    /// connections immediately so they send GOAWAY(NO_ERROR) and drain in-flight
    /// handlers without waiting for `idle_timeout_ms` (#42).
    pub fn requestStop(self: *Server) void {
        self.stop.store(true, .release);
        self.stop_event.set(self.io);
    }
};

const TimedOp = union(enum) { work: anyerror!void, timer: void };

fn timerThunk(io: Io, ms: u64) void {
    Io.sleep(io, .{ .nanoseconds = @as(i96, ms) * std.time.ns_per_ms }, .awake) catch {};
}

/// Runs blocking `f(args...)` (must return anyerror!void) raced against a `ms`
/// deadline; `error.Timeout` when the deadline wins. The loser is canceled —
/// the std.Io backend interrupts the blocked syscall (one-shot; callers close
/// the connection on timeout rather than retrying). `ms == 0` = no deadline.
pub fn runTimed(io: Io, ms: u64, f: anytype, args: anytype) anyerror!void {
    if (ms == 0) return @call(.auto, f, args);
    var buf: [2]TimedOp = undefined;
    var sel = Io.Select(TimedOp).init(io, &buf);
    // Spawn the timer first so if only one concurrency slot is available and
    // `.work` fails to spawn, `.work` is never cancelled mid-flight after
    // consuming bytes from the underlying reader.
    sel.concurrent(.timer, timerThunk, .{ io, ms }) catch return @call(.auto, f, args);
    sel.concurrent(.work, f, args) catch {
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
    /// Poisoned on any writeAll/flush failure so concurrent writers never emit
    /// misaligned frames after a partial frame landed on the wire.
    broken: bool = false,
    /// Armed atomically with SETTINGS(ACK) when peer reduces
    /// SETTINGS_HEADER_TABLE_SIZE; consumed by the very next outbound HEADERS.
    pending_hpack_zero: bool = false,

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

    fn writeCombinedChunkLocked(self: *ConnWriter, ftype: FrameType, flags: u8, sid: u31, prefix: []const u8, block: []const u8, start: usize, end: usize) !void {
        var hdr: [9]u8 = undefined;
        putHeader(&hdr, end - start, ftype, flags, sid);
        try self.w.writeAll(&hdr);
        if (start < prefix.len) {
            const p_end = @min(end, prefix.len);
            try self.w.writeAll(prefix[start..p_end]);
            if (end > prefix.len) try self.w.writeAll(block[0 .. end - prefix.len]);
        } else if (end > start) {
            try self.w.writeAll(block[start - prefix.len .. end - prefix.len]);
        }
    }

    fn writeHeaderBlockLocked(self: *ConnWriter, sid: u31, end_stream: bool, max_frame: usize, prefix: []const u8, block: []const u8) !void {
        const es: u8 = if (end_stream) flag_end_stream else 0;
        const total = prefix.len + block.len;
        if (total <= max_frame) {
            try self.writeCombinedChunkLocked(.headers, flag_end_headers | es, sid, prefix, block, 0, total);
        } else {
            try self.writeCombinedChunkLocked(.headers, es, sid, prefix, block, 0, max_frame);
            var off: usize = max_frame;
            while (off < total) {
                const end = @min(off + max_frame, total);
                const last = end == total;
                try self.writeCombinedChunkLocked(.continuation, if (last) flag_end_headers else 0, sid, prefix, block, off, end);
                off = end;
            }
        }
    }

    fn ackSettings(self: *ConnWriter, emit_hpack_zero: bool) !void {
        self.lock();
        defer self.unlock();
        if (self.broken) return error.WriteFailed;
        if (emit_hpack_zero) self.pending_hpack_zero = true;
        self.frameLocked(.settings, flag_ack, 0, "") catch |err| {
            self.broken = true;
            return err;
        };
        self.w.flush() catch |err| {
            self.broken = true;
            return err;
        };
    }

    /// Writes one self-contained frame (lock + flush).
    fn frame(self: *ConnWriter, ftype: FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        self.lock();
        defer self.unlock();
        if (self.broken) return error.WriteFailed;
        self.frameLocked(ftype, flags, sid, payload) catch |err| {
            self.broken = true;
            return err;
        };
        self.w.flush() catch |err| {
            self.broken = true;
            return err;
        };
    }

    /// Writes one stream frame while re-checking `st.reset`/`closing` under the
    /// writer lock so a worker can never emit HEADERS/DATA after the reader
    /// already wrote RST_STREAM for the same stream (RFC 9113 §5.1).
    fn frameForStream(self: *ConnWriter, st: *H2Stream, ftype: FrameType, flags: u8, payload: []const u8) !void {
        self.lock();
        defer self.unlock();
        if (self.broken) return error.WriteFailed;
        if (st.reset.load(.acquire) or st.conn.closing.load(.acquire)) return error.StreamReset;
        self.frameLocked(ftype, flags, st.id, payload) catch |err| {
            self.broken = true;
            st.conn.closing.store(true, .release);
            return err;
        };
        self.w.flush() catch |err| {
            self.broken = true;
            st.conn.closing.store(true, .release);
            return err;
        };
    }
};

/// Bounded circular byte buffer for `H2Stream` request bodies. Keeps memory
/// O(initial_window_size) during sustained streaming uploads even when the
/// handler never drains the buffer completely to zero (#35).
const RxRing = struct {
    buf: []u8 = &.{},
    head: usize = 0,
    len: usize = 0,

    fn deinit(self: *RxRing, gpa: std.mem.Allocator) void {
        if (self.buf.len > 0) gpa.free(self.buf);
        self.* = .{};
    }

    fn appendSlice(self: *RxRing, gpa: std.mem.Allocator, data: []const u8) !void {
        if (data.len == 0) return;
        const needed = try std.math.add(usize, self.len, data.len);
        if (needed > self.buf.len) {
            var new_cap: usize = if (self.buf.len == 0) 4096 else self.buf.len;
            while (new_cap < needed) {
                new_cap = std.math.mul(usize, new_cap, 2) catch needed;
            }
            const new_buf = try gpa.alloc(u8, new_cap);
            if (self.len > 0) {
                const first = @min(self.len, self.buf.len - self.head);
                @memcpy(new_buf[0..first], self.buf[self.head..][0..first]);
                if (first < self.len) {
                    @memcpy(new_buf[first..self.len], self.buf[0 .. self.len - first]);
                }
            }
            if (self.buf.len > 0) gpa.free(self.buf);
            self.buf = new_buf;
            self.head = 0;
        }
        const tail = (self.head + self.len) % self.buf.len;
        const first = @min(data.len, self.buf.len - tail);
        @memcpy(self.buf[tail..][0..first], data[0..first]);
        if (first < data.len) {
            @memcpy(self.buf[0 .. data.len - first], data[first..]);
        }
        self.len += data.len;
    }

    fn read(self: *RxRing, dst: []u8) usize {
        const n = @min(self.len, dst.len);
        if (n == 0) return 0;
        const first = @min(n, self.buf.len - self.head);
        @memcpy(dst[0..first], self.buf[self.head..][0..first]);
        if (first < n) {
            @memcpy(dst[first..n], self.buf[0 .. n - first]);
        }
        self.len -= n;
        if (self.len == 0) {
            self.head = 0;
        } else {
            self.head = (self.head + n) % self.buf.len;
        }
        return n;
    }
};

/// Per-connection anti-flood accounting for control frames (non-ACK PING,
/// non-ACK SETTINGS, PRIORITY) and consecutive empty non-END_STREAM DATA
/// frames (CVE-2019-9512 / 9515 / 9518, #36). Reader-thread-only.
///
/// Uses a fixed 11-slot sliding ring (10 full sub-buckets of `window_ns / 10`
/// plus the current partially-elapsed bucket, weighting the oldest slot by its
/// remaining overlap) advanced by exact `elapsed / slot_ns` steps so bursts
/// near the tail of a window stay accurately counted with O(1) time and zero
/// heap allocations.
const FloodGuard = struct {
    const bucket_count: usize = 10;
    const slot_count: usize = bucket_count + 1;

    slot_start_ns: ?i96 = null,
    slots: [slot_count]u32 = @splat(0),
    slot_head: usize = 0,
    slot_total: u64 = 0,
    consecutive_empty_data: u32 = 0,

    /// Records one control/empty frame at `now_ns`. Returns true when the
    /// sliding-window budget is exceeded.
    fn recordControl(self: *FloodGuard, now_ns: i96, cfg: Config) bool {
        const limit = cfg.max_control_frames_per_window;
        if (limit == 0) return false;
        const window_ms = cfg.control_frame_window_ms;
        if (window_ms == 0) {
            self.slot_total +|= 1;
            return self.slot_total > limit;
        }
        const window_ns: i96 = @as(i96, window_ms) * std.time.ns_per_ms;
        const slot_ns: i96 = @max(@as(i96, 1), @divTrunc(window_ns, bucket_count));
        const start = self.slot_start_ns orelse blk: {
            self.slot_start_ns = now_ns;
            break :blk now_ns;
        };
        const elapsed = @max(@as(i96, 0), now_ns - start);
        const steps = @divTrunc(elapsed, slot_ns);
        if (steps >= slot_count) {
            self.slots = @splat(0);
            self.slot_head = 0;
            self.slot_total = 0;
            self.slot_start_ns = now_ns;
        } else if (steps > 0) {
            var s: usize = @intCast(steps);
            while (s > 0) : (s -= 1) {
                self.slot_head = (self.slot_head + 1) % slot_count;
                self.slot_total -= self.slots[self.slot_head];
                self.slots[self.slot_head] = 0;
            }
            self.slot_start_ns = start + steps * slot_ns;
        }
        self.slots[self.slot_head] +|= 1;
        self.slot_total +|= 1;

        const oldest = self.slots[(self.slot_head + 1) % slot_count];
        const sub_elapsed = @min(slot_ns, @max(@as(i96, 0), now_ns - self.slot_start_ns.?));
        const oldest_rem = slot_ns - sub_elapsed;
        const oldest_weighted: u64 = if (oldest == 0 or oldest_rem == 0)
            0
        else
            @intCast(@divTrunc(@as(i128, oldest) * oldest_rem + slot_ns - 1, slot_ns));
        const effective_total = (self.slot_total - oldest) + oldest_weighted;
        return effective_total > limit;
    }

    /// Records one empty non-END_STREAM DATA frame. Returns true when either
    /// the consecutive empty-DATA cap or the control-frame window cap trips.
    fn recordEmptyData(self: *FloodGuard, now_ns: i96, cfg: Config) bool {
        self.consecutive_empty_data +|= 1;
        if (cfg.max_empty_data_frames > 0 and self.consecutive_empty_data > cfg.max_empty_data_frames) {
            return true;
        }
        return self.recordControl(now_ns, cfg);
    }

    fn resetEmptyData(self: *FloodGuard) void {
        self.consecutive_empty_data = 0;
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
    /// True once the server has emitted the response's final END_STREAM. Used
    /// to distinguish normal client RST_STREAM cleanup after an early response
    /// (client send half still open) from a rapid-reset flood.
    response_finished: std.atomic.Value(bool) = .init(false),
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
    rx_buf: RxRing = .{}, // gpa-backed circular buffer; freed by the worker
    rx_eof: bool = false,
    /// Total unpadded DATA payload bytes received on this stream, checked
    /// against `req.content_length` (RFC 9113 §8.1.1). Guarded by `rx_mu`.
    rx_body_bytes: u64 = 0,

    /// Inbound (receive) flow-control window: bytes the peer may still send on
    /// this stream. Initialized to the advertised SETTINGS_INITIAL_WINDOW_SIZE;
    /// decremented on receipt, credited back as the handler consumes. rx_mu.
    recv_window: i64 = 0,
    /// Consumed-but-not-yet-acknowledged bytes, batched into a WINDOW_UPDATE
    /// once past half the initial window. rx_mu.
    recv_pending: i64 = 0,

    /// Per-RPC deadline (absolute awake-clock timestamp), guarded by `deadline_mu`.
    deadline: ?Io.Timestamp = null,
    deadline_mu: Io.Mutex = .init,
    timed_out: std.atomic.Value(bool) = .init(false),
    /// Set by the worker as it exits (one-way, never cleared); the watchdog
    /// uses it to distinguish "worker finished" from "re-armed".
    done: std.atomic.Value(bool) = .init(false),
    /// Whether the watchdog has been started (worker-thread-only; no lock needed).
    armed: bool = false,
    /// Merged wakeup: set when the worker finishes (after setting `done`) or
    /// when `armDeadline` re-arms; the watchdog `reset`s it after handling.
    wake_event: Io.Event = .unset,
    /// Set by the watchdog just before it exits; the worker waits on this
    /// before freeing `self` (replaces the old `deadline_thread.join()`).
    watchdog_done: Io.Event = .unset,

    /// Sets/tightens/extends the per-RPC deadline; the first call starts the
    /// watchdog, subsequent calls wake it up to re-read the new deadline.
    /// Only called from this stream's worker thread (handler → ctx.setDeadline).
    fn armDeadline(self: *H2Stream, deadline: Io.Timestamp) void {
        const conn = self.conn;
        self.deadline_mu.lockUncancelable(conn.io);
        self.deadline = deadline; // write the deadline (source of truth) first
        self.deadline_mu.unlock(conn.io);
        if (!self.armed) {
            self.armed = true;
            if (!spawnTask(conn, deadlineWaiter, .{self})) self.armed = false;
        } else {
            self.wake_event.set(conn.io); // wake the existing watchdog to re-read the (possibly earlier) deadline
        }
    }

    fn arena(self: *H2Stream) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// rx_mu held. Records `amt` consumed/acknowledged bytes; returns the
    /// WINDOW_UPDATE increment to emit for this stream (0 if below threshold).
    fn creditStreamLocked(self: *H2Stream, amt: i64) i64 {
        self.recv_pending += amt;
        const threshold = @max(@as(i64, 1), @divTrunc(@as(i64, clampInitialWindow(self.conn.srv.config.initial_window_size)), 2));
        if (self.recv_pending >= threshold) {
            const d = self.recv_pending;
            self.recv_window += d;
            self.recv_pending = 0;
            return d;
        }
        return 0;
    }

    /// `types.BodyReader` backend: blocks until request bytes are available,
    /// returns 0 at END_STREAM, errors on reset/teardown.
    fn streamRead(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        const conn = self.conn;
        var waiting = false;
        defer if (waiting) conn.notePeerWaitEnd();
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
            if (self.rx_buf.len > 0) {
                const n = self.rx_buf.read(buf);
                // Credit the stream flow-control window for consumed bytes.
                const d = if (n > 0) self.creditStreamLocked(@intCast(n)) else 0;
                self.rx_mu.unlock(conn.io);
                if (waiting) {
                    conn.notePeerWaitEnd();
                    waiting = false;
                }
                const dc = if (n > 0) creditConn(conn, @intCast(n)) else 0;
                sendWindowUpdates(conn, self.id, d, dc);
                return n;
            }
            if (self.rx_eof) {
                self.rx_mu.unlock(conn.io);
                return 0;
            }
            if (!waiting) {
                conn.notePeerWaitBegin();
                waiting = true;
            }
            self.rx_cond.waitUncancelable(conn.io, &self.rx_mu);
        }
    }

    fn bodyReader(self: *H2Stream) types.BodyReader {
        return .{ .ctx = self, .readFn = streamRead };
    }

    /// Sends `data` as flow-controlled DATA frames (never END_STREAM). Blocks
    /// while the send window is empty; errors if the stream/connection tears down.
    fn sendBody(self: *H2Stream, data: []const u8) !void {
        return self.sendBodyImpl(data, false);
    }

    /// Sends `data` as flow-controlled DATA frames. When `end_stream` is true,
    /// sets `END_STREAM` on the final DATA frame directly (or sends a 0-byte
    /// DATA(END_STREAM) if `data.len == 0`).
    fn sendBodyImpl(self: *H2Stream, data: []const u8, end_stream: bool) !void {
        if (data.len == 0) {
            if (end_stream) try self.endStream();
            return;
        }
        const conn = self.conn;
        var off: usize = 0;
        while (off < data.len) {
            conn.send_mu.lockUncancelable(conn.io);
            const n = blk: {
                var waiting = false;
                defer if (waiting) conn.notePeerWaitEnd();
                while (true) {
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
                        const want: i64 = @min(@as(i64, @intCast(data.len - off)), @min(avail, @as(i64, conn.peer.max_frame_size.load(.acquire))));
                        self.send_window -= want;
                        conn.send_window -= want;
                        break :blk @as(usize, @intCast(want));
                    }
                    if (!waiting) {
                        conn.notePeerWaitBegin();
                        waiting = true;
                    }
                    conn.send_cond.waitUncancelable(conn.io, &conn.send_mu);
                }
            };
            conn.send_mu.unlock(conn.io);
            const is_last = off + n == data.len;
            const flags: u8 = if (end_stream and is_last) flag_end_stream else 0;
            conn.cw.frameForStream(self, .data, flags, data[off .. off + n]) catch |err| {
                if (err == error.StreamReset) {
                    // Frame was not written on the wire; return both stream and connection send credit.
                    conn.send_mu.lockUncancelable(conn.io);
                    self.send_window += @as(i64, @intCast(n));
                    conn.send_window += @as(i64, @intCast(n));
                    conn.send_cond.broadcast(conn.io);
                    conn.send_mu.unlock(conn.io);
                }
                return err;
            };
            off += n;
        }
    }

    fn endStream(self: *H2Stream) !void {
        try self.conn.cw.frameForStream(self, .data, flag_end_stream, "");
    }
};

/// `types.Context.setDeadline` backend: arms the stream's deadline watchdog.
fn h2SetDeadline(opaque_ctx: *anyopaque, deadline: Io.Timestamp) void {
    const st: *H2Stream = @ptrCast(@alignCast(opaque_ctx));
    st.armDeadline(deadline);
}

/// Fires the timeout: flips `timed_out` and wakes any body/response I/O
/// blocked on `rx_cond`/`send_cond`. Kept distinct from `reset` (which means
/// the peer or protocol layer already RST the stream) so `runStream` still
/// closes the stream on the wire when the handler exits unfinished.
fn fireDeadline(st: *H2Stream) void {
    const conn = st.conn;
    st.timed_out.store(true, .release);
    st.rx_mu.lockUncancelable(conn.io);
    st.rx_cond.broadcast(conn.io);
    st.rx_mu.unlock(conn.io);
    conn.send_mu.lockUncancelable(conn.io);
    conn.send_cond.broadcast(conn.io);
    conn.send_mu.unlock(conn.io);
}

/// Watchdog task: blocks on a single `wake_event` until the deadline arrives,
/// the worker finishes, or the deadline is re-armed. No polling, no nested
/// task spawning (`waitTimeout` is a single underlying `futexWaitTimeout`).
fn deadlineWaiter(st: *H2Stream) void {
    const conn = st.conn;
    while (true) {
        st.deadline_mu.lockUncancelable(conn.io);
        const dl = st.deadline.?;
        st.deadline_mu.unlock(conn.io);

        st.wake_event.waitTimeout(conn.io, .{ .deadline = dl.withClock(.awake) }) catch |err| switch (err) {
            error.Timeout => {
                // Timer fired or spurious wakeup: re-check against the current deadline.
                const now = Io.Timestamp.now(conn.io, .awake);
                st.deadline_mu.lockUncancelable(conn.io);
                const cur = st.deadline.?;
                st.deadline_mu.unlock(conn.io);
                if (now.nanoseconds >= cur.nanoseconds) {
                    fireDeadline(st);
                    break;
                }
                continue; // spurious wakeup / deadline extended → re-wait with the latest dl
            },
            else => break, // error.Canceled → exit without firing
        };

        // wake_event was set: worker finished, or we were re-armed.
        if (st.done.load(.acquire)) break; // worker finished → do not fire
        st.wake_event.reset(); // claim this wakeup (not currently waiting, so reset's precondition holds)
        if (st.done.load(.acquire)) break; // re-check: don't lose a `done` racing the reset
        // otherwise this was a re-arm (tighten/extend) → loop back with the new dl
    }
    st.watchdog_done.set(conn.io); // the watchdog's last touch of `st`
    // The watchdog is also a spawnTask-counted task; give back the count on exit
    // (touches only `conn`):
    conn.workers_mu.lockUncancelable(conn.io);
    conn.active_workers -= 1;
    conn.workers_cond.broadcast(conn.io);
    conn.workers_mu.unlock(conn.io);
}

/// Response sink that frames a handler's output onto an HTTP/2 stream.
const H2Sink = struct {
    stream: *H2Stream,

    const vtable: types.Sink.Vtable = .{
        .sendHead = sendHead,
        .writeBody = writeBody,
        .finish = finish,
        .sendComplete = sendComplete,
    };

    fn sink(self: *H2Sink) types.Sink {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn sendHead(ctx: *anyopaque, res: *types.Response) anyerror!void {
        const self: *H2Sink = @ptrCast(@alignCast(ctx));
        if (self.stream.reset.load(.acquire) or self.stream.conn.closing.load(.acquire)) return error.StreamReset;
        var block: std.ArrayList(u8) = .empty;
        const hdrs = try buildResponseHeaders(res);
        try hpack.Encoder.encodeResponse(res.arena, &block, res.status_code, hdrs);
        try self.stream.conn.writeHeaders(self.stream, block.items, false);
    }

    fn writeBody(ctx: *anyopaque, _: *types.Response, bytes: []const u8) anyerror!void {
        const self: *H2Sink = @ptrCast(@alignCast(ctx));
        try self.stream.sendBody(bytes);
    }

    /// Coalesced fast path for known-length / empty responses (#41): emits
    /// `HEADERS(END_STREAM)` when `body` is empty, or `HEADERS` + first `DATA`
    /// (with `END_STREAM` when it fits) in a single `cw.lock()` and `flush()`.
    fn sendComplete(ctx: *anyopaque, res: *types.Response, body: []const u8) anyerror!void {
        const self: *H2Sink = @ptrCast(@alignCast(ctx));
        const st = self.stream;
        const conn = st.conn;
        if (st.timed_out.load(.acquire)) return error.DeadlineExceeded;
        if (st.reset.load(.acquire) or conn.closing.load(.acquire)) return error.StreamReset;

        var block: std.ArrayList(u8) = .empty;
        const hdrs = try buildResponseHeaders(res);
        try hpack.Encoder.encodeResponse(res.arena, &block, res.status_code, hdrs);

        if (body.len == 0) {
            try conn.writeHeadersWithData(st, block.items, "", true);
            st.response_finished.store(true, .release);
            return;
        }

        var first_n: usize = 0;
        conn.send_mu.lockUncancelable(conn.io);
        if (st.timed_out.load(.acquire)) {
            conn.send_mu.unlock(conn.io);
            return error.DeadlineExceeded;
        }
        if (st.reset.load(.acquire) or conn.closing.load(.acquire)) {
            conn.send_mu.unlock(conn.io);
            return error.StreamReset;
        }
        const avail = @min(st.send_window, conn.send_window);
        if (avail > 0) {
            const want: i64 = @min(@as(i64, @intCast(body.len)), @min(avail, @as(i64, conn.peer.max_frame_size.load(.acquire))));
            st.send_window -= want;
            conn.send_window -= want;
            first_n = @intCast(want);
        }
        conn.send_mu.unlock(conn.io);

        if (first_n > 0) {
            const fits_all = first_n == body.len;
            conn.writeHeadersWithData(st, block.items, body[0..first_n], fits_all) catch |err| {
                if (err == error.StreamReset) {
                    conn.send_mu.lockUncancelable(conn.io);
                    st.send_window += @as(i64, @intCast(first_n));
                    conn.send_window += @as(i64, @intCast(first_n));
                    conn.send_cond.broadcast(conn.io);
                    conn.send_mu.unlock(conn.io);
                }
                return err;
            };
            res.head_sent = true;
            if (!fits_all) {
                try st.sendBodyImpl(body[first_n..], true);
            }
        } else {
            try conn.writeHeadersWithData(st, block.items, "", false);
            res.head_sent = true;
            try st.sendBodyImpl(body, true);
        }
        st.response_finished.store(true, .release);
    }

    fn finish(ctx: *anyopaque, res: *types.Response) anyerror!void {
        const self: *H2Sink = @ptrCast(@alignCast(ctx));
        if (self.stream.reset.load(.acquire) or self.stream.conn.closing.load(.acquire)) return error.StreamReset;
        if (res.trailers.items.len > 0) {
            // Trailing HEADERS carry END_STREAM (e.g. gRPC grpc-status).
            const items = res.trailers.items;
            const hdrs = try res.arena.alloc(hpack.Header, items.len);
            for (items, 0..) |h, i| hdrs[i] = .{ .name = h.name, .value = h.value };
            var block: std.ArrayList(u8) = .empty;
            try hpack.Encoder.encodeTrailers(res.arena, &block, hdrs);
            try self.stream.conn.writeHeaders(self.stream, block.items, true);
        } else {
            try self.stream.endStream();
        }
        self.stream.response_finished.store(true, .release);
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
    /// Highest client-initiated stream ID seen on inbound HEADERS (including
    /// refused streams), used to distinguish idle vs closed stream IDs.
    highest_stream_id: u31 = 0,
    /// Highest client-initiated stream ID accepted for processing (for GOAWAY).
    last_stream_id: u31 = 0,
    /// Last stream ID emitted in any prior GOAWAY, keeping subsequent GOAWAY
    /// frames monotonically non-increasing (RFC 9113 §6.8).
    goaway_last_id: ?u31 = null,
    // Rapid-reset accounting (CVE-2023-44487), guarded by streams_mu.
    streams_opened: u32 = 0,
    streams_reset: u32 = 0,
    // One-shot fixed-size ring (256 slots, 2x the default max_concurrent_streams)
    // of stream IDs whose response completed cleanly (END_STREAM sent) while the
    // client's send half was still open (!rx_eof). A single trailing RST_STREAM
    // from the client closing that half-closed stream is normal HTTP/2 cleanup
    // rather than a rapid-reset attack. Entries evicted past the 256-stream
    // backlog fall back to normal reset counting. Guarded by streams_mu.
    early_closed: [256]u31 = @splat(0),
    early_closed_pos: usize = 0,

    // Worker accounting (for graceful drain).
    workers_mu: Io.Mutex = .init,
    workers_cond: Io.Condition = .init,
    active_workers: u32 = 0,
    /// Count of workers currently blocked on peer frames (rx DATA or send WINDOW_UPDATE).
    peer_waiters: u32 = 0,
    /// Monotonic timestamp (ns, `.awake`) when `peer_waiters` rose from 0 to >0;
    /// cleared when `peer_waiters` returns to 0 so streams making real progress
    /// reset the window while housekeeping frames (PING, SETTINGS) do not.
    peer_wait_since_ns: ?i96 = null,
    /// Monotonic timestamp (ns, `.awake`) when graceful drain started (`enterDraining`).
    drain_started_ns: ?i96 = null,
    // Worker task group: workers and watchdogs are added as tasks here; drained together via await.
    worker_group: Io.Group = .init,

    // Inbound (receive) flow control, connection-level. recv_mu (leaf lock).
    recv_mu: Io.Mutex = .init,
    conn_recv_window: i64 = 65535,
    conn_recv_pending: i64 = 0,

    /// Set on graceful shutdown (peer GOAWAY(NO_ERROR) or Server.stop). Reader-
    /// thread-only: new streams are refused while in-flight workers finish.
    draining: bool = false,
    closing: std.atomic.Value(bool) = .init(false),
    /// Reusable inbound frame payload scratch buffer (reader-thread-only, #41).
    rx_scratch: std.ArrayList(u8) = .empty,
    /// Control-frame and empty-DATA flood accounting (reader-thread-only, #36).
    flood: FloodGuard = .{},

    fn deinit(self: *Connection) void {
        // Workers have all exited (drainWorkers ran) and removed their streams.
        self.rx_scratch.deinit(self.gpa);
        self.streams.deinit(self.gpa);
        self.decoder.deinit();
    }

    /// Borrows a reusable reader-thread scratch slice of length `needed`,
    /// growing on demand (starting at 16 KiB) up to `max_frame_size`.
    fn borrowScratch(self: *Connection, needed: usize) ![]u8 {
        if (needed == 0) return &.{};
        if (self.rx_scratch.capacity < needed) {
            try self.rx_scratch.ensureTotalCapacity(self.gpa, @max(@as(usize, our_max_frame_size), needed));
        }
        self.rx_scratch.items.len = needed;
        return self.rx_scratch.items;
    }

    fn enterDraining(self: *Connection) void {
        if (self.draining) return;
        self.draining = true;
        const now = Io.Timestamp.now(self.io, .awake).nanoseconds;
        self.workers_mu.lockUncancelable(self.io);
        self.drain_started_ns = now;
        self.workers_cond.broadcast(self.io);
        self.workers_mu.unlock(self.io);
    }

    fn notePeerWaitBegin(self: *Connection) void {
        const now = Io.Timestamp.now(self.io, .awake).nanoseconds;
        self.workers_mu.lockUncancelable(self.io);
        if (self.peer_waiters == 0) self.peer_wait_since_ns = now;
        self.peer_waiters += 1;
        self.workers_cond.broadcast(self.io);
        self.workers_mu.unlock(self.io);
    }

    fn notePeerWaitEnd(self: *Connection) void {
        self.workers_mu.lockUncancelable(self.io);
        self.peer_waiters -= 1;
        if (self.peer_waiters == 0) self.peer_wait_since_ns = null;
        self.workers_cond.broadcast(self.io);
        self.workers_mu.unlock(self.io);
    }

    fn sendOurSettings(self: *Connection) !void {
        const cfg = self.srv.config;
        const cwnd = clampConnWindow(cfg.connection_window_size);
        self.conn_recv_window = cwnd;
        var p: [36]u8 = undefined; // 6 entries * 6 bytes
        putSetting(p[0..6], set_enable_push, 0);
        putSetting(p[6..12], set_max_concurrent_streams, cfg.max_concurrent_streams);
        putSetting(p[12..18], set_header_table_size, our_header_table_size);
        putSetting(p[18..24], set_max_frame_size, effectiveMaxFrameSize(cfg));
        putSetting(p[24..30], set_initial_window_size, clampInitialWindow(cfg.initial_window_size));
        putSetting(p[30..36], set_max_header_list_size, @intCast(self.decoder.max_list_size));

        // Coalesce initial SETTINGS + stream-0 WINDOW_UPDATE into a single lock + flush.
        self.cw.lock();
        defer self.cw.unlock();
        if (self.cw.broken) return error.WriteFailed;
        self.cw.frameLocked(.settings, 0, 0, &p) catch |err| {
            self.cw.broken = true;
            return err;
        };
        if (cwnd > 65535) {
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, @intCast((cwnd - 65535) & 0x7fff_ffff), .big);
            self.cw.frameLocked(.window_update, 0, 0, &wu) catch |err| {
                self.cw.broken = true;
                return err;
            };
        }
        self.cw.w.flush() catch |err| {
            self.cw.broken = true;
            return err;
        };
    }

    /// Wakes any worker blocked on a flow-control window (after WINDOW_UPDATE,
    /// reset, or teardown).
    fn wakeSenders(self: *Connection) void {
        self.send_mu.lockUncancelable(self.io);
        self.send_cond.broadcast(self.io);
        self.send_mu.unlock(self.io);
    }

    /// HEADERS (+ CONTINUATION when the block exceeds the peer's max frame size),
    /// emitted atomically so no other stream's frames interleave. Re-checks
    /// `st.reset`/`closing` under `cw.mu` so no HEADERS can follow RST_STREAM,
    /// and prepends HPACK Dynamic Table Size Update (0) if pending after
    /// acknowledging a peer SETTINGS_HEADER_TABLE_SIZE reduction.
    fn writeHeaders(self: *Connection, st: *H2Stream, block: []const u8, end_stream: bool) !void {
        return self.writeHeadersWithData(st, block, "", end_stream);
    }

    /// Emits HEADERS (+ CONTINUATION if needed) and an optional DATA frame
    /// inside a single `cw.mu` lock + single `flush()`. When `data` is empty
    /// and `end_stream` is true, sets `END_STREAM` directly on HEADERS.
    fn writeHeadersWithData(
        self: *Connection,
        st: *H2Stream,
        block: []const u8,
        data: []const u8,
        end_stream: bool,
    ) !void {
        const max: usize = self.peer.max_frame_size.load(.acquire);
        const sid = st.id;
        self.cw.lock();
        defer self.cw.unlock();
        if (self.cw.broken) return error.WriteFailed;
        if (st.reset.load(.acquire) or self.closing.load(.acquire)) return error.StreamReset;
        var pbuf: [10]u8 = undefined;
        const prefix: []const u8 = if (self.cw.pending_hpack_zero) blk: {
            self.cw.pending_hpack_zero = false;
            break :blk hpack.Encoder.encodeTableSizeUpdate(0, &pbuf);
        } else &[_]u8{};
        const hdr_end_stream = end_stream and data.len == 0;
        self.cw.writeHeaderBlockLocked(sid, hdr_end_stream, max, prefix, block) catch |err| {
            self.cw.broken = true;
            self.closing.store(true, .release);
            return err;
        };
        if (data.len > 0) {
            const data_flags: u8 = if (end_stream) flag_end_stream else 0;
            self.cw.frameLocked(.data, data_flags, sid, data) catch |err| {
                self.cw.broken = true;
                self.closing.store(true, .release);
                return err;
            };
        }
        self.cw.w.flush() catch |err| {
            self.cw.broken = true;
            self.closing.store(true, .release);
            return err;
        };
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

    /// Waits for all in-flight workers/watchdogs to exit. On real teardown
    /// (`graceful == false`: EOF, read error, idle timeout, fatal GOAWAY/error),
    /// flips `closing` immediately so blocked workers abort; on graceful
    /// shutdown (`graceful == true`: peer GOAWAY(NO_ERROR) or Server.stop),
    /// leaves `closing` clear until `active_workers` reaches 0 so in-flight
    /// handlers can finish reading buffered bodies and writing responses.
    fn drainWorkers(self: *Connection, graceful: bool) void {
        if (!graceful) {
            self.closing.store(true, .release);
            self.wakeSenders(); // release any window-blocked workers
            self.wakeReceivers(); // release any rx-blocked streaming workers
        }
        self.workers_mu.lockUncancelable(self.io);
        while (self.active_workers > 0) self.workers_cond.waitUncancelable(self.io, &self.workers_mu);
        self.workers_mu.unlock(self.io);
        self.closing.store(true, .release);
        // All tasks have exited (counter hit 0); await releases the group's own resources and returns immediately.
        self.worker_group.await(self.io) catch {};
    }
};

fn readSliceThunk(r: *Io.Reader, buf: []u8) anyerror!void {
    return r.readSliceAll(buf);
}

fn readVecThunk(r: *Io.Reader, buf: []u8) anyerror!usize {
    var bufs = [_][]u8{buf};
    return r.readVec(&bufs);
}

/// Deadline-bounded readSliceAll; skips the timer when the bytes are already
/// buffered (the common case for a payload right after its frame header).
fn readSliceTimed(conn: *Connection, r: *Io.Reader, buf: []u8, ms: u64) !void {
    if (r.bufferedLen() >= buf.len) return r.readSliceAll(buf);
    return runTimed(conn.io, ms, readSliceThunk, .{ r, buf });
}

const IdleWait = enum { stopped, timeout, canceled };
const IdleReadOp = union(enum) { work: anyerror!usize, wait: IdleWait };
const IdleHeaderResult = enum { frame, stopped };

/// Coarse interval at which `idleWaitThunk` checks async-signal-safe
/// `Server.stop` when callers only `store(true)` without calling `requestStop()`.
/// Loops internally without cancelling the peer `readVec`.
const stop_poll_ns: i96 = 200 * std.time.ns_per_ms;

fn idleWaitThunk(srv: *Server, idle_timeout_ms: u64) IdleWait {
    const deadline_ns: ?i96 = if (idle_timeout_ms > 0)
        Io.Timestamp.now(srv.io, .awake).nanoseconds + @as(i96, idle_timeout_ms) * std.time.ns_per_ms
    else
        null;
    while (true) {
        if (srv.stop.load(.acquire)) return .stopped;
        var wait_ns: i96 = stop_poll_ns;
        if (deadline_ns) |dl| {
            const now = Io.Timestamp.now(srv.io, .awake).nanoseconds;
            if (now >= dl) return .timeout;
            wait_ns = @min(wait_ns, dl - now);
        }
        srv.stop_event.waitTimeout(srv.io, .{
            .duration = .{ .raw = .{ .nanoseconds = wait_ns }, .clock = .awake },
        }) catch |err| switch (err) {
            // Re-check `srv.stop` and `deadline_ns` (also handles spurious wakeups).
            error.Timeout => continue,
            error.Canceled => return .canceled,
        };
        return .stopped;
    }
}

/// Reads the next 9-byte frame header while idle, racing `Server.stop_event`
/// (with optional `idle_timeout_ms` and coarse `Server.stop` checks) so both
/// `Server.requestStop()` and bare signal-safe `Server.stop.store(true)` wake
/// idle connections promptly instead of waiting for `idle_timeout_ms` (#42).
/// Preserves partial header bytes via `readVec` so an in-flight header is never
/// silently truncated across a stop wakeup.
fn readIdleHeader(conn: *Connection, r: *Io.Reader, hb: *[9]u8) !IdleHeaderResult {
    if (conn.srv.stop.load(.acquire)) return .stopped;
    const buffered = r.buffered();
    if (buffered.len >= hb.len) {
        try r.readSliceAll(hb);
        return .frame;
    }
    if (buffered.len > 0) {
        const got = buffered.len;
        @memcpy(hb[0..got], buffered);
        r.toss(got);
        try readSliceTimed(conn, r, hb[got..], conn.srv.config.head_timeout_ms);
        return .frame;
    }

    var buf: [2]IdleReadOp = undefined;
    var sel = Io.Select(IdleReadOp).init(conn.io, &buf);
    // Spawn the stop/timeout waiter first so `.work` is never cancelled
    // mid-flight if concurrency is unavailable.
    sel.concurrent(.wait, idleWaitThunk, .{ conn.srv, conn.srv.config.idle_timeout_ms }) catch {
        try r.readSliceAll(hb);
        return .frame;
    };
    sel.concurrent(.work, readVecThunk, .{ r, hb[0..] }) catch {
        while (sel.cancel()) |_| {}
        try r.readSliceAll(hb);
        return .frame;
    };
    const first = try sel.await();
    var got_n: ?usize = switch (first) {
        .work => |res| if (res) |n| n else |_| null,
        .wait => null,
    };
    var work_err: ?anyerror = switch (first) {
        .work => |res| if (res) |_| null else |e| e,
        .wait => null,
    };
    var wait_res: ?IdleWait = switch (first) {
        .wait => |w| w,
        .work => null,
    };
    while (sel.cancel()) |leftover| switch (leftover) {
        .work => |res| if (res) |n| {
            got_n = n;
        } else |e| {
            if (work_err == null) work_err = e;
        },
        .wait => |w| {
            wait_res = w;
        },
    };
    if (got_n) |n| {
        if (n == 0) return error.EndOfStream;
        if (n < hb.len) try readSliceTimed(conn, r, hb[n..], conn.srv.config.head_timeout_ms);
        return .frame;
    }
    // `Io.Reader.readVec` wraps cancellation as `error.ReadFailed`, so treat
    // `work_err` as a real transport error only when `.work` won `await()` or
    // explicitly returned `EndOfStream` (never caused by cancellation).
    if (first == .work) return work_err orelse error.Canceled;
    if (work_err) |e| if (e == error.EndOfStream) return error.EndOfStream;
    if (wait_res) |w| switch (w) {
        .stopped => return .stopped,
        .timeout => return error.Timeout,
        .canceled => {},
    };
    return work_err orelse error.Canceled;
}

const DrainOp = union(enum) { work: anyerror!void, drained: bool, timeout: bool };

fn waitWorkersDrained(conn: *Connection) bool {
    conn.workers_mu.lockUncancelable(conn.io);
    defer conn.workers_mu.unlock(conn.io);
    while (conn.active_workers > 0) {
        conn.workers_cond.wait(conn.io, &conn.workers_mu) catch return false;
    }
    return true;
}

fn peerWaitBoundMs(cfg: Config) u64 {
    if (cfg.head_timeout_ms > 0 and cfg.idle_timeout_ms > 0) return @min(cfg.head_timeout_ms, cfg.idle_timeout_ms);
    return if (cfg.head_timeout_ms > 0) cfg.head_timeout_ms else cfg.idle_timeout_ms;
}

/// Caller holds `conn.workers_mu`. Returns the earliest anchored deadline (ns,
/// `.awake`) at which the drain read loop must stop and flip `closing`, or null
/// when no deadline is currently active.
fn nextDrainDeadlineNsLocked(conn: *const Connection) ?i96 {
    const cfg = conn.srv.config;
    var earliest: ?i96 = null;
    if (cfg.drain_timeout_ms > 0) {
        if (conn.drain_started_ns) |ds| {
            earliest = ds + @as(i96, cfg.drain_timeout_ms) * std.time.ns_per_ms;
        }
    }
    if (conn.peer_waiters > 0) {
        const peer_ms = peerWaitBoundMs(cfg);
        if (peer_ms > 0) {
            const since = conn.peer_wait_since_ns.?;
            const base = if (conn.drain_started_ns) |ds| @max(since, ds) else since;
            const dl = base + @as(i96, peer_ms) * std.time.ns_per_ms;
            earliest = if (earliest) |e| @min(e, dl) else dl;
        }
    }
    return earliest;
}

fn drainTimerThunk(conn: *Connection) bool {
    conn.workers_mu.lockUncancelable(conn.io);
    while (conn.active_workers > 0) {
        const dl = nextDrainDeadlineNsLocked(conn) orelse {
            conn.workers_cond.wait(conn.io, &conn.workers_mu) catch {
                conn.workers_mu.unlock(conn.io);
                return false;
            };
            continue;
        };
        const now = Io.Timestamp.now(conn.io, .awake).nanoseconds;
        if (now >= dl) {
            conn.workers_mu.unlock(conn.io);
            return true;
        }
        const rem_ns = dl - now;
        conn.workers_mu.unlock(conn.io);
        Io.sleep(conn.io, .{ .nanoseconds = rem_ns }, .awake) catch return false;
        conn.workers_mu.lockUncancelable(conn.io);
        if (conn.active_workers == 0) break;
        if (nextDrainDeadlineNsLocked(conn)) |cur_dl| {
            if (Io.Timestamp.now(conn.io, .awake).nanoseconds >= cur_dl) {
                conn.workers_mu.unlock(conn.io);
                return true;
            }
        }
    }
    conn.workers_mu.unlock(conn.io);
    return false;
}

/// While draining, reads the next frame header so in-flight streams can still
/// receive DATA/trailers/WINDOW_UPDATE/RST_STREAM, while exiting promptly the
/// moment `active_workers` reaches 0. Deadlines are anchored on `Connection`
/// (`drain_started_ns` for `drain_timeout_ms`, and `peer_wait_since_ns` when
/// `peer_waiters` rises above 0) rather than per-frame, so housekeeping traffic
/// like keepalive PINGs cannot extend a stalled drain indefinitely.
///
/// Returns `true` when `hb` holds a frame header, `false` when all workers have
/// drained, or an error on EOF / read error / drain deadline expiry.
fn readDrainHeader(conn: *Connection, r: *Io.Reader, hb: *[9]u8) !bool {
    conn.workers_mu.lockUncancelable(conn.io);
    const done_now = conn.active_workers == 0;
    const expired_now = if (!done_now) blk: {
        if (nextDrainDeadlineNsLocked(conn)) |dl| {
            break :blk Io.Timestamp.now(conn.io, .awake).nanoseconds >= dl;
        }
        break :blk false;
    } else false;
    conn.workers_mu.unlock(conn.io);
    if (done_now) return false;
    if (expired_now) return error.Timeout;

    if (r.bufferedLen() >= hb.len) {
        try r.readSliceAll(hb);
        return true;
    }

    var buf: [3]DrainOp = undefined;
    var sel = Io.Select(DrainOp).init(conn.io, &buf);
    sel.concurrent(.drained, waitWorkersDrained, .{conn}) catch {
        try r.readSliceAll(hb);
        return true;
    };
    sel.concurrent(.work, readSliceThunk, .{ r, hb }) catch {
        while (sel.cancel()) |leftover| switch (leftover) {
            .drained => |d| if (d) return false,
            .work => {},
            .timeout => {},
        };
        try r.readSliceAll(hb);
        return true;
    };
    sel.concurrent(.timeout, drainTimerThunk, .{conn}) catch {};
    const first = try sel.await();
    var work_ok = switch (first) {
        .work => |res| if (res) |_| true else |_| false,
        .drained, .timeout => false,
    };
    var work_err: ?anyerror = switch (first) {
        .work => |res| if (res) |_| null else |e| e,
        .drained, .timeout => null,
    };
    var drained = switch (first) {
        .drained => |d| d,
        .work, .timeout => false,
    };
    var timed_out = switch (first) {
        .timeout => |t| t,
        .work, .drained => false,
    };
    while (sel.cancel()) |leftover| switch (leftover) {
        .work => |res| if (res) |_| {
            work_ok = true;
        } else |e| {
            if (work_err == null) work_err = e;
        },
        .drained => |d| if (d) {
            drained = true;
        },
        .timeout => |t| if (t) {
            timed_out = true;
        },
    };
    // Prefer a completed header read over the drained signal so the 9 bytes
    // already consumed into `hb` (e.g. a fatal GOAWAY) are parsed rather than
    // discarded; the next loop iteration observes `active_workers == 0`.
    if (work_ok) return true;
    if (drained) return false;
    if (timed_out) return error.Timeout;
    return work_err orelse error.Canceled;
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
    const graceful = readLoop(&conn, r);
    conn.drainWorkers(graceful);
}

/// Returns true on graceful shutdown (peer GOAWAY(NO_ERROR) or Server.stop)
/// so in-flight workers finish cleanly; returns false on teardown (EOF, read
/// error, idle timeout, fatal protocol error, or non-NO_ERROR GOAWAY).
fn readLoop(conn: *Connection, r: *Io.Reader) bool {
    var goaway_sent = false;
    var peer_settings_seen = false;
    while (true) {
        if (!goaway_sent and conn.srv.stop.load(.acquire)) {
            conn.enterDraining();
            sendGoaway(conn, .no_error);
            goaway_sent = true;
        }
        // Idle deadline (+ immediate Server.stop_event wakeup) on the next frame
        // header; a shorter head_timeout_ms deadline on the payload it announces.
        var hb: [9]u8 = undefined;
        if (conn.draining) {
            const has_frame = readDrainHeader(conn, r, &hb) catch return false;
            if (!has_frame) return true;
        } else {
            const res = readIdleHeader(conn, r, &hb) catch return false; // EOF / error / idle -> done
            if (res == .stopped) {
                if (!goaway_sent) {
                    conn.enterDraining();
                    sendGoaway(conn, .no_error);
                    goaway_sent = true;
                }
                continue;
            }
        }
        const fh = parseHeader(&hb);
        if (fh.length > effectiveMaxFrameSize(conn.srv.config)) {
            sendGoaway(conn, .frame_size_error);
            return false;
        }
        const payload = conn.borrowScratch(fh.length) catch return false;
        if (payload.len > 0) {
            readSliceTimed(conn, r, payload, conn.srv.config.head_timeout_ms) catch return false;
        }

        if (validateInboundFrame(fh, payload)) |code| {
            sendGoaway(conn, code);
            return false;
        }

        // RFC 9113 §3.4: the client connection preface MUST be followed by a
        // non-ACK SETTINGS frame; any other initial frame is a PROTOCOL_ERROR.
        const is_initial_settings = !peer_settings_seen;
        if (!peer_settings_seen) {
            if (fh.ftype != .settings or (fh.flags & flag_ack != 0)) {
                sendGoaway(conn, .protocol_error);
                return false;
            }
            peer_settings_seen = true;
        }

        switch (fh.ftype) {
            .settings => {
                if ((fh.flags & flag_ack == 0) and !is_initial_settings) {
                    const now_ns = Io.Timestamp.now(conn.io, .awake).nanoseconds;
                    if (conn.flood.recordControl(now_ns, conn.srv.config)) {
                        sendGoaway(conn, .enhance_your_calm);
                        return false;
                    }
                }
                if (!handleSettings(conn, fh, payload)) return false;
            },
            .window_update => if (!handleWindowUpdate(conn, fh, payload)) return false,
            .ping => {
                if (fh.flags & flag_ack == 0) {
                    const now_ns = Io.Timestamp.now(conn.io, .awake).nanoseconds;
                    if (conn.flood.recordControl(now_ns, conn.srv.config)) {
                        sendGoaway(conn, .enhance_your_calm);
                        return false;
                    }
                    conn.cw.frame(.ping, flag_ack, 0, payload) catch return false;
                }
            },
            .headers => handleHeaders(conn, r, fh, payload) catch return false,
            .data => if (!handleData(conn, fh, payload)) return false,
            .rst_stream => if (!resetStream(conn, fh.sid)) return false,
            .goaway => {
                // RFC 7540 §6.8: GOAWAY(NO_ERROR) is graceful — stop accepting
                // new streams and let in-flight streams finish. Any non-zero
                // error code tears down immediately.
                const code = std.mem.readInt(u32, payload[4..8], .big);
                if (code != @backingInt(ErrorCode.no_error)) return false;
                conn.enterDraining();
            },
            .priority => {
                // No-op prioritization, but still bounded against PRIORITY floods (#36).
                const now_ns = Io.Timestamp.now(conn.io, .awake).nanoseconds;
                if (conn.flood.recordControl(now_ns, conn.srv.config)) {
                    sendGoaway(conn, .enhance_your_calm);
                    return false;
                }
            },
            .continuation => {
                // handleHeaders consumes an in-sequence CONTINUATION inline, so
                // one reaching here has no HEADERS to continue: a connection
                // PROTOCOL_ERROR (RFC 9113 §6.10). Ignoring it also dropped a
                // header-block fragment on the floor, desyncing HPACK.
                sendGoaway(conn, .protocol_error);
                return false;
            },
            .push_promise => {
                // A client cannot push (RFC 9113 §6.6) and we advertised
                // SETTINGS_ENABLE_PUSH=0: connection PROTOCOL_ERROR. The frame
                // also carries a header-block fragment, so dropping it silently
                // would leave our HPACK table one block behind the peer's for
                // the rest of the connection.
                sendGoaway(conn, .protocol_error);
                return false;
            },
            else => {},
        }
    }
}

/// Returns a connection-error code when `fh`/`payload` violate framing rules
/// (RFC 7540 §4/§6), or null when the frame is structurally acceptable.
/// Shared with the client: see `proto.validateInboundFrame`.
const validateInboundFrame = proto2.validateInboundFrame;

/// Returns false on a connection-fatal SETTINGS (GOAWAY already sent).
fn handleSettings(conn: *Connection, fh: ParsedHeader, payload: []const u8) bool {
    if (fh.flags & flag_ack != 0) return true; // our settings were acked
    var i: usize = 0;
    var min_hts: ?u32 = null;
    var last_hts: ?u32 = null;
    while (i + 6 <= payload.len) : (i += 6) {
        const id = std.mem.readInt(u16, payload[i..][0..2], .big);
        const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
        switch (id) {
            set_header_table_size => {
                min_hts = if (min_hts) |m| @min(m, val) else val;
                last_hts = val;
            },
            set_initial_window_size => {
                // A window over 2^31-1 is a connection FLOW_CONTROL_ERROR
                // (RFC 9113 §6.5.2). Apply immediately in wire order (§6.5) so
                // an intermediate overflow cannot be hidden by a later setting.
                if (val > 0x7fff_ffff) {
                    sendGoaway(conn, .flow_control_error);
                    return false;
                }
                if (!applyInitialWindow(conn, val)) return false;
            },
            set_max_frame_size => {
                // RFC 7540 §6.5.2: a value outside [2^14, 2^24-1] MUST be a
                // connection error of type PROTOCOL_ERROR. Left unchecked, a 0
                // (or any tiny value) also drove sendBody/writeHeaders into a
                // zero-length-frame busy loop.
                if (val < our_max_frame_size or val > 16777215) {
                    sendGoaway(conn, .protocol_error);
                    return false;
                }
                conn.peer.max_frame_size.store(val, .release);
            },
            set_enable_push => {
                // RFC 9113 §6.5.2: SETTINGS_ENABLE_PUSH must be 0 or 1; any
                // other value is a connection PROTOCOL_ERROR.
                if (val > 1) {
                    sendGoaway(conn, .protocol_error);
                    return false;
                }
            },
            else => {}, // max_concurrent_streams: we do not initiate streams
        }
    }
    var emit_hpack_zero = false;
    if (min_hts) |m| {
        if (m < conn.peer.header_table_size) emit_hpack_zero = true;
        conn.peer.header_table_size = last_hts.?;
    }
    conn.cw.ackSettings(emit_hpack_zero) catch return false;
    return true;
}

/// Apply a SETTINGS_INITIAL_WINDOW_SIZE change: shift every live stream's send
/// window by the delta and rebase new-stream initial size (RFC 7540 §6.9.2).
/// Returns false (after GOAWAY, written outside `streams_mu`/`send_mu`) when
/// the shift pushes any window past 2^31-1 — a connection FLOW_CONTROL_ERROR.
fn applyInitialWindow(conn: *Connection, new_iw: u32) bool {
    var overflow = false;
    {
        conn.streams_mu.lockUncancelable(conn.io);
        defer conn.streams_mu.unlock(conn.io);
        const delta: i64 = @as(i64, new_iw) - @as(i64, conn.peer.initial_window_size);
        conn.peer.initial_window_size = new_iw;
        if (delta == 0) return true;
        conn.send_mu.lockUncancelable(conn.io);
        defer conn.send_mu.unlock(conn.io);
        var it = conn.streams.valueIterator();
        while (it.next()) |st| {
            if (st.*.reset.load(.acquire)) continue;
            // Each window is <= 2^31-1 and |delta| < 2^31, so the sum cannot
            // overflow i64; a result over 2^31-1 is the illegal state itself.
            st.*.send_window += delta;
            if (st.*.send_window > 0x7fff_ffff) overflow = true;
        }
        conn.send_cond.broadcast(conn.io);
    }
    if (overflow) {
        sendGoaway(conn, .flow_control_error);
        return false;
    }
    return true;
}

/// Returns false on a connection-fatal WINDOW_UPDATE (GOAWAY already sent).
fn handleWindowUpdate(conn: *Connection, fh: ParsedHeader, payload: []const u8) bool {
    if (payload.len < 4) return true;
    // RFC 9113 §5.1 / §6.9: WINDOW_UPDATE on an idle stream (never-opened even
    // id or id above the highest client stream seen) is a connection PROTOCOL_ERROR.
    if (fh.sid != 0 and (fh.sid % 2 == 0 or fh.sid > conn.highest_stream_id)) {
        sendGoaway(conn, .protocol_error);
        return false;
    }
    const incr: i64 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
    // A 0 increment is a PROTOCOL_ERROR: connection-level -> GOAWAY, stream-level
    // -> RST_STREAM (RFC 7540 §6.9).
    if (incr == 0) {
        if (fh.sid == 0) {
            sendGoaway(conn, .protocol_error);
            return false;
        }
        conn.streams_mu.lockUncancelable(conn.io);
        if (conn.streams.get(fh.sid)) |st| {
            st.reset.store(true, .release);
            st.rx_mu.lockUncancelable(conn.io);
            st.rx_cond.broadcast(conn.io);
            st.rx_mu.unlock(conn.io);
        }
        conn.streams_mu.unlock(conn.io);
        conn.wakeSenders();
        rstStreamCode(conn, fh.sid, .protocol_error);
        return true;
    }
    var conn_overflow = false;
    var stream_overflow = false;
    {
        conn.streams_mu.lockUncancelable(conn.io);
        defer conn.streams_mu.unlock(conn.io);
        var overflow_st: ?*H2Stream = null;
        {
            conn.send_mu.lockUncancelable(conn.io);
            defer conn.send_mu.unlock(conn.io);
            // The flow-control window must not exceed 2^31-1 (RFC 7540 §6.9.1):
            // connection overflow is fatal; stream overflow resets just that stream.
            if (fh.sid == 0) {
                if (conn.send_window + incr > 0x7fff_ffff) {
                    conn_overflow = true;
                } else {
                    conn.send_window += incr;
                }
            } else if (conn.streams.get(fh.sid)) |st| {
                if (!st.reset.load(.acquire)) {
                    if (st.send_window + incr > 0x7fff_ffff) {
                        st.reset.store(true, .release);
                        overflow_st = st;
                        stream_overflow = true;
                    } else {
                        st.send_window += incr;
                    }
                }
            }
            conn.send_cond.broadcast(conn.io);
        }
        // Wake any worker blocked in streamRead (lock order: streams_mu -> rx_mu).
        if (overflow_st) |st| {
            st.rx_mu.lockUncancelable(conn.io);
            st.rx_cond.broadcast(conn.io);
            st.rx_mu.unlock(conn.io);
        }
    }
    if (conn_overflow) {
        sendGoaway(conn, .flow_control_error);
        return false;
    }
    if (stream_overflow) {
        rstStreamCode(conn, fh.sid, .flow_control_error);
    }
    return true;
}

/// Hard cap on one request's accumulated header block across HEADERS +
/// CONTINUATION frames; past it the connection gets GOAWAY ENHANCE_YOUR_CALM.
const max_header_block_bytes: usize = 256 * 1024;

/// Cap on CONTINUATION frames per header block. Bytes are already bounded by
/// max_header_block_bytes, but zero-length CONTINUATION frames make no byte
/// progress, so a peer could stream them forever (CVE-2024-27316 class); this
/// bounds the frame count independently. A legitimate block needs only a
/// handful (256KiB / 16KiB max frame ⇒ ~16), so this is generous.
const max_continuation_frames: usize = 256;

/// Rapid-reset mitigation (CVE-2023-44487): a peer that streams HEADERS→
/// RST_STREAM pairs keeps `streams.count()` near zero so the concurrency cap
/// never fires, yet forces unbounded decode/dispatch/teardown work. Once a
/// connection has reset more than this many streams AND resets exceed half the
/// streams it opened, we GOAWAY ENHANCE_YOUR_CALM. The floor tolerates the
/// occasional legitimate cancel; the ratio catches a flood.
const rapid_reset_floor: u32 = 100;

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

    // Deliver request DATA to the stream's worker via its rx channel. Every
    // stream runs a worker (spawned at HEADERS) that reads the body through
    // `ctx.body_reader`, so there is one body path for all requests. Hold
    // streams_mu across the whole delivery so the worker (which takes
    // streams_mu in removeStream before freeing the stream) cannot free `s`
    // out from under us. Lock order matches wakeReceivers/resetStream:
    // streams_mu -> rx_mu.
    conn.streams_mu.lockUncancelable(conn.io);
    const s = conn.streams.get(fh.sid) orelse {
        var half_closed_local = false;
        for (&conn.early_closed) |*slot| {
            if (slot.* == fh.sid) {
                half_closed_local = true;
                if (end_stream) slot.* = 0; // peer now closed its send half too
                break;
            }
        }
        conn.streams_mu.unlock(conn.io);
        // DATA on an id we never opened: idle (even push id or above the highest
        // id seen) is a connection PROTOCOL_ERROR; closed (at or below it) is a
        // stream error — RST STREAM_CLOSED, keeping the connection (RFC 9113
        // §5.1/§6.1). Silently dropping the frame let a peer stream DATA on idle
        // ids forever.
        if (fh.sid % 2 == 0 or fh.sid > conn.highest_stream_id) {
            sendGoaway(conn, .protocol_error);
            return false;
        }
        // The frame still consumed connection-level window even though no
        // stream will ever read it — flush the credit immediately.
        if (payload.len > 0) {
            const d = creditConnEx(conn, @intCast(payload.len), true);
            if (d > 0) sendWindowUpdate(conn, 0, d);
        }
        // If we responded early without reading the request body, the stream is
        // still half-closed (local) from the client's perspective, so in-flight
        // DATA is valid and silently discarded instead of reset (RFC 9113 §5.1).
        if (!half_closed_local) rstStreamCode(conn, fh.sid, .stream_closed);
        if (data.len == 0 and !end_stream) {
            const now_ns = Io.Timestamp.now(conn.io, .awake).nanoseconds;
            if (conn.flood.recordEmptyData(now_ns, conn.srv.config)) {
                sendGoaway(conn, .enhance_your_calm);
                return false;
            }
        } else {
            conn.flood.resetEmptyData();
        }
        return true;
    };
    s.rx_mu.lockUncancelable(conn.io);
    const fc_len: i64 = @intCast(payload.len);
    if (s.reset.load(.acquire)) {
        // Stream was already reset (e.g. peer RST_STREAM or earlier stream error)
        // while its worker is still unwinding: discard DATA without buffering,
        // return connection-level flow-control credit immediately, and keep
        // empty-DATA flood accounting active.
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        if (fc_len > 0) {
            const dc = creditConnEx(conn, fc_len, true);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
        if (data.len == 0 and !end_stream) {
            const now_ns = Io.Timestamp.now(conn.io, .awake).nanoseconds;
            if (conn.flood.recordEmptyData(now_ns, conn.srv.config)) {
                sendGoaway(conn, .enhance_your_calm);
                return false;
            }
        } else {
            conn.flood.resetEmptyData();
        }
        return true;
    }
    if (s.rx_eof) {
        // Already half-closed(remote) (END_STREAM seen): RFC 7540 §5.1 requires
        // RST_STREAM(STREAM_CLOSED) rather than buffering unread DATA. Return
        // the connection-window credit deducted above and wake the worker.
        s.reset.store(true, .release);
        s.rx_cond.broadcast(conn.io);
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        conn.wakeSenders();
        if (fc_len > 0) {
            const dc = creditConnEx(conn, fc_len, true);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
        rstStreamCode(conn, fh.sid, .stream_closed);
        return true;
    }
    // Inbound stream flow control: deduct the full frame length (padding counts).
    s.recv_window -= fc_len;
    if (s.recv_window < 0) {
        // Peer exceeded the window we advertised: reset just this stream.
        s.reset.store(true, .release);
        s.rx_cond.broadcast(conn.io);
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        conn.wakeSenders();
        {
            const dc = creditConnEx(conn, fc_len, true);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
        rstStreamCode(conn, fh.sid, .flow_control_error);
        return true;
    }
    // RFC 9113 §8.1.1: total unpadded DATA length MUST match content-length.
    const cl_mismatch = blk: {
        const new_total = std.math.add(u64, s.rx_body_bytes, data.len) catch break :blk true;
        if (s.req.content_length) |cl| {
            if (new_total > cl or (end_stream and new_total != cl)) break :blk true;
        }
        s.rx_body_bytes = new_total;
        break :blk false;
    };
    if (cl_mismatch) {
        s.reset.store(true, .release);
        s.rx_cond.broadcast(conn.io);
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        conn.wakeSenders();
        if (fc_len > 0) {
            const dc = creditConnEx(conn, fc_len, true);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
        rstStreamCode(conn, fh.sid, .protocol_error);
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
        conn.wakeSenders();
        {
            const dc = creditConnEx(conn, fc_len, true);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
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
    // CVE-2019-9518: cap consecutive empty (0 body byte) non-END_STREAM DATA frames.
    if (data.len == 0 and !end_stream) {
        const now_ns = Io.Timestamp.now(conn.io, .awake).nanoseconds;
        if (conn.flood.recordEmptyData(now_ns, conn.srv.config)) {
            sendGoaway(conn, .enhance_your_calm);
            return false;
        }
    } else {
        conn.flood.resetEmptyData();
    }
    const dc = if (overhead > 0) creditConn(conn, overhead) else 0;
    sendWindowUpdates(conn, fh.sid, d, dc);
    return true;
}

/// Handles a peer RST_STREAM. Returns false (after sending GOAWAY) when the
/// stream is idle (RFC 9113 §6.4) or the connection crossed the rapid-reset threshold.
fn resetStream(conn: *Connection, sid: u31) bool {
    if (sid % 2 == 0 or sid > conn.highest_stream_id) {
        sendGoaway(conn, .protocol_error);
        return false;
    }
    var excused = false;
    conn.streams_mu.lockUncancelable(conn.io);
    if (conn.streams.get(sid)) |st| {
        const prev_reset = st.reset.swap(true, .acq_rel);
        // Wake a streaming worker blocked reading request DATA.
        st.rx_mu.lockUncancelable(conn.io);
        if (!prev_reset and st.response_finished.load(.acquire) and !st.rx_eof) {
            excused = true;
        }
        st.rx_cond.broadcast(conn.io);
        st.rx_mu.unlock(conn.io);
    } else {
        // Consume one-shot exemption for a stream whose response already
        // finished early while the client's request half remained open.
        for (&conn.early_closed) |*slot| {
            if (slot.* == sid) {
                slot.* = 0;
                excused = true;
                break;
            }
        }
    }
    var flood = false;
    if (!excused) {
        // Count every non-excused peer reset, even one racing the stream's own
        // teardown — a rapid-reset attacker's RST often lands after the worker
        // already removed the stream, so gating on `streams.get` would miss
        // the flood entirely.
        conn.streams_reset +%= 1;
        flood = conn.streams_reset > rapid_reset_floor and
            conn.streams_reset > conn.streams_opened / 2;
    }
    conn.streams_mu.unlock(conn.io);
    conn.wakeSenders();
    if (flood) {
        sendGoaway(conn, .enhance_your_calm);
        return false;
    }
    return true;
}

fn sendGoaway(conn: *Connection, code: ErrorCode) void {
    const lid: u31 = if (conn.goaway_last_id) |prev| @min(prev, conn.last_stream_id) else conn.last_stream_id;
    conn.goaway_last_id = lid;
    var p: [8]u8 = undefined;
    std.mem.writeInt(u32, p[0..4], @as(u32, lid), .big);
    std.mem.writeInt(u32, p[4..8], @backingInt(code), .big);
    conn.cw.frame(.goaway, 0, 0, &p) catch {};
}

/// Reads a (possibly CONTINUATION-extended) header block, decodes it, builds a
/// Request, and spawns a worker. Returns error only on fatal transport failure.
fn handleHeaders(conn: *Connection, r: *Io.Reader, fh: ParsedHeader, first: []const u8) !void {
    const gpa = conn.gpa;

    // Strip PADDED / PRIORITY prefixes from the first fragment. A prefix that
    // does not fit the payload is a connection PROTOCOL_ERROR (RFC 9113 §6.2):
    // returning quietly instead left the stream with no response at all *and*
    // skipped the HPACK decode below, desyncing the decoder for the rest of the
    // connection.
    var frag = first;
    if (fh.flags & flag_padded != 0) {
        if (frag.len == 0) {
            sendGoaway(conn, .protocol_error);
            return error.ProtocolError;
        }
        const pad = frag[0];
        frag = frag[1..];
        if (pad > frag.len) {
            sendGoaway(conn, .protocol_error);
            return error.ProtocolError;
        }
        frag = frag[0 .. frag.len - pad];
    }
    if (fh.flags & flag_priority != 0) {
        if (frag.len < 5) {
            sendGoaway(conn, .protocol_error);
            return error.ProtocolError;
        }
        frag = frag[5..];
    }

    if (frag.len > max_header_block_bytes) {
        sendGoaway(conn, .enhance_your_calm);
        return error.ProtocolError;
    }

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, frag);

    // Pull CONTINUATION frames until END_HEADERS (no interleaving permitted).
    // The accumulated block is hard-capped: an attacker streaming CONTINUATION
    // frames forever must not grow `block` without bound (CVE-2024-27316 class).
    if (fh.flags & flag_end_headers == 0) {
        var cont_frames: usize = 0;
        while (true) {
            var hb: [9]u8 = undefined;
            try readSliceTimed(conn, r, &hb, conn.srv.config.head_timeout_ms);
            const cf = parseHeader(&hb);
            if (cf.ftype != .continuation or cf.sid != fh.sid) {
                // A header block must not be interleaved with any other frame
                // (RFC 9113 §6.10) — a connection error, so say so on the wire
                // rather than just dropping the connection.
                sendGoaway(conn, .protocol_error);
                return error.ProtocolError;
            }
            if (cf.length > effectiveMaxFrameSize(conn.srv.config)) {
                sendGoaway(conn, .frame_size_error);
                return error.ProtocolError;
            }
            cont_frames += 1;
            if (cont_frames > max_continuation_frames) {
                // Zero-length CONTINUATION frames never grow `block`, so the byte
                // cap below can't stop an endless stream of them; cap the count.
                sendGoaway(conn, .enhance_your_calm);
                return error.ProtocolError;
            }
            if (block.items.len + cf.length > max_header_block_bytes) {
                sendGoaway(conn, .enhance_your_calm);
                return error.ProtocolError;
            }
            if (cf.length > 0) {
                try block.ensureUnusedCapacity(gpa, cf.length);
                const prev_len = block.items.len;
                const dst = block.addManyAsSliceAssumeCapacity(cf.length);
                readSliceTimed(conn, r, dst, conn.srv.config.head_timeout_ms) catch |err| {
                    block.items.len = prev_len;
                    return err;
                };
            }
            if (cf.flags & flag_end_headers != 0) break;
        }
    }

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
    // closed stream (e.g. in-flight trailers arriving after an early response):
    // RFC 9113 §5.1 requires minimally processing the header block to keep HPACK
    // in sync without tearing down the connection; we decode and discard via
    // `refuseStream` (sending RST_STREAM(STREAM_CLOSED)).
    if (fh.sid <= conn.highest_stream_id) return refuseStream(conn, fh.sid, block.items, .stream_closed);
    conn.highest_stream_id = fh.sid;

    // Graceful shutdown: stop accepting new streams once the server is stopping
    // or the peer sent a graceful GOAWAY. Refuse this one while in-flight
    // streams keep draining (without advancing last_stream_id).
    if (conn.srv.stop.load(.acquire) or conn.draining) return refuseStream(conn, fh.sid, block.items, .refused_stream);

    // Concurrency cap.
    conn.streams_mu.lockUncancelable(conn.io);
    const count = conn.streams.count();
    conn.streams_mu.unlock(conn.io);
    if (count >= conn.srv.config.max_concurrent_streams) {
        return refuseStream(conn, fh.sid, block.items, .refused_stream);
    }

    // Build the stream (owns its request arena). Decode happens on this (reader)
    // thread so the HPACK decoder stays single-threaded.
    const st = gpa.create(H2Stream) catch return refuseStream(conn, fh.sid, block.items, .internal_error);
    st.* = .{
        .conn = conn,
        .id = fh.sid,
        .arena_state = std.heap.ArenaAllocator.init(gpa),
        .req = undefined,
        .send_window = conn.peer.initial_window_size,
        .recv_window = @intCast(clampInitialWindow(conn.srv.config.initial_window_size)),
    };
    const arena = st.arena();
    const decoded = conn.decoder.decode(arena, block.items) catch |err| {
        st.arena_state.deinit();
        gpa.destroy(st);
        sendGoaway(conn, if (err == error.OutOfMemory) .internal_error else .compression_error);
        return error.ProtocolError;
    };
    conn.last_stream_id = fh.sid;
    st.req = buildRequest(arena, decoded) catch |err| {
        st.arena_state.deinit();
        gpa.destroy(st);
        // Either way the stream gets a reset: without one the peer waits for a
        // response that will never come.
        rstStreamCode(conn, fh.sid, if (err == error.BadRequest) .protocol_error else .internal_error);
        return;
    };
    // RFC 9113 §8.1.1: a bodyless request (END_STREAM on HEADERS) with a
    // non-zero content-length is malformed.
    if (fh.flags & flag_end_stream != 0) {
        if (st.req.content_length) |cl| {
            if (cl != 0) {
                st.arena_state.deinit();
                gpa.destroy(st);
                rstStreamCode(conn, fh.sid, .protocol_error);
                return;
            }
        }
        st.rx_eof = true;
    } else {
        st.has_body = true;
    }

    conn.streams_mu.lockUncancelable(conn.io);
    conn.streams.put(gpa, fh.sid, st) catch {
        conn.streams_mu.unlock(conn.io);
        st.arena_state.deinit();
        gpa.destroy(st);
        rstStreamCode(conn, fh.sid, .internal_error);
        return;
    };
    conn.streams_opened +%= 1;
    conn.streams_mu.unlock(conn.io);

    // Dispatch the worker as soon as headers decode. The request body (if any)
    // streams to the handler through `ctx.body_reader`; a bodyless request
    // (END_STREAM on HEADERS) has `rx_eof` preset so the reader returns 0.
    spawnWorker(conn, st);
}

/// Rejects one stream with `code` while keeping the connection usable.
///
/// The header block MUST still be fed to the HPACK decoder even though nobody
/// will see the fields: HPACK's dynamic table is connection-wide state built
/// from every block in wire order (RFC 7541 §2.2), independent of which streams
/// we choose to serve. Skipping the decode leaves our table one entry behind the
/// peer's, and from then on every indexed reference on the connection resolves
/// to the wrong field — silently, with no error anywhere. Refusing at
/// `max_concurrent_streams` is ordinary behaviour, not an attack, so this path
/// is routine; in a proxy the mismatch is a header-smuggling primitive.
///
/// Returns an error only when the block itself is malformed, which is
/// connection-fatal (GOAWAY already sent).
fn refuseStream(conn: *Connection, sid: u31, block: []const u8, code: ErrorCode) !void {
    decodeDiscard(conn, block) catch |err| {
        sendGoaway(conn, if (err == error.OutOfMemory) .internal_error else .compression_error);
        return error.ProtocolError;
    };
    rstStreamCode(conn, sid, code);
}

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
    const decoded = conn.decoder.decode(tmp.allocator(), block) catch |err| {
        sendGoaway(conn, if (err == error.OutOfMemory) .internal_error else .compression_error); // HPACK failure is connection-fatal (RFC 9113 §4.3)
        return error.ProtocolError;
    };

    // Trailers must carry END_STREAM and must not contain pseudo-headers or
    // malformed field names/values (RFC 9113 §8.1 / §8.2.1).
    var invalid_code: ?ErrorCode = null;
    if (fh.flags & flag_end_stream == 0) {
        invalid_code = .protocol_error;
    } else for (decoded) |h| {
        // RFC 9113 §8.2.2: connection-specific headers and `te` are forbidden in trailers.
        if (!proto2.isValidFieldName(h.name) or !proto2.isValidFieldValue(h.value) or
            isConnectionSpecificHeader(h.name) or std.mem.eql(u8, h.name, "te"))
        {
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
    if (s.reset.load(.acquire)) {
        // Already reset while worker is unwinding; HPACK was decoded above.
        s.rx_mu.unlock(conn.io);
        conn.streams_mu.unlock(conn.io);
        return;
    }
    // Already half-closed (END_STREAM seen) → HEADERS after end is STREAM_CLOSED;
    // otherwise bad trailers or content-length mismatch → protocol_error.
    const cl_bad = if (s.req.content_length) |cl| s.rx_body_bytes != cl else false;
    const rst_code: ?ErrorCode = if (s.rx_eof) .stream_closed else (invalid_code orelse (if (cl_bad) .protocol_error else null));
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

/// Launches a connection task: prefers the Io backend (Io.Group.concurrent) to let
/// the backend choose between threads and fibers; falls back to a detached OS thread
/// if the backend has no concurrency support. Increments active_workers on success
/// (tasks decrement on exit); returns false only if both paths fail. f's return type
/// must coerce to Io.Cancelable!void (void satisfies); args is f's ArgsTuple, matching
/// the parameter expectations of Io.Group.concurrent / std.Thread.spawn.
fn spawnTask(conn: *Connection, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f))) bool {
    conn.workers_mu.lockUncancelable(conn.io);
    conn.active_workers += 1;
    conn.workers_mu.unlock(conn.io);
    conn.worker_group.concurrent(conn.io, f, args) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            const t = std.Thread.spawn(.{}, f, args) catch {
                conn.workers_mu.lockUncancelable(conn.io);
                conn.active_workers -= 1;
                conn.workers_mu.unlock(conn.io);
                return false;
            };
            t.detach();
        },
    };
    return true;
}

/// Registers worker accounting and spawns the per-stream worker task.
fn spawnWorker(conn: *Connection, st: *H2Stream) void {
    if (spawnTask(conn, runStream, .{st})) return;
    // Neither a group task nor a fallback thread could start: reclaim the
    // stream. HEADERS were already decoded and acknowledged, so without an
    // explicit RST the peer waits for a response that will never come.
    rstStreamCode(conn, st.id, .refused_stream);
    removeStream(conn, st.id);
    st.rx_buf.deinit(conn.gpa);
    st.arena_state.deinit();
    conn.gpa.destroy(st);
}

fn buildRequest(arena: std.mem.Allocator, decoded: []const hpack.Header) !types.Request {
    var method: []const u8 = "";
    var scheme: []const u8 = "";
    var path: []const u8 = "";
    var authority: []const u8 = "";
    var host: ?[]const u8 = null;
    var content_length: ?u64 = null;
    var cookie_idx: ?usize = null;
    var cookie_count: usize = 0;
    var cookie_total_len: usize = 0;
    var hdrs: std.ArrayList(types.Header) = .empty;
    var saw_regular = false;

    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;

    for (decoded) |h| {
        // RFC 9113 §8.2.1: field names MUST NOT be empty; field values MUST NOT
        // have leading/trailing SP/HTAB or any CTL octets (0x00-0x08, 0x0a-0x1f, 0x7f).
        if (h.name.len == 0) return error.BadRequest;
        if (!proto2.isValidFieldValue(h.value)) return error.BadRequest;
        if (h.name[0] == ':') {
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
        // RFC 9113 §8.2.1 & §8.2.2: lowercase field name syntax + no connection headers.
        if (!proto2.isValidFieldName(h.name)) return error.BadRequest;
        if (isConnectionSpecificHeader(h.name)) return error.BadRequest;
        if (std.mem.eql(u8, h.name, "te") and !std.mem.eql(u8, h.value, "trailers")) return error.BadRequest;
        if (std.mem.eql(u8, h.name, "content-length")) {
            const cl = proto2.parseContentLength(h.value) orelse return error.BadRequest;
            if (content_length) |first| {
                if (first != cl) return error.BadRequest;
                continue; // identical duplicate: forward the field once
            }
            content_length = cl;
        }
        if (std.mem.eql(u8, h.name, "host")) {
            if (host != null or h.value.len == 0) return error.BadRequest;
            for (h.value) |ch| if (ch <= 0x20 or ch >= 0x7f or ch == '@') return error.BadRequest;
            host = h.value;
        }
        // RFC 9113 §8.2.3: defer joining multiple `cookie` fields to a single
        // O(N) arena allocation after the loop (#34).
        if (std.mem.eql(u8, h.name, "cookie")) {
            if (cookie_idx != null) {
                cookie_count += 1;
                const sep_and_val = std.math.add(usize, 2, h.value.len) catch return error.OutOfMemory;
                cookie_total_len = std.math.add(usize, cookie_total_len, sep_and_val) catch return error.OutOfMemory;
                continue;
            }
            cookie_idx = hdrs.items.len;
            cookie_count = 1;
            cookie_total_len = h.value.len;
        }
        try hdrs.append(arena, .{ .name = h.name, .value = h.value });
    }

    if (cookie_count > 1) {
        const joined = try arena.alloc(u8, cookie_total_len);
        var pos: usize = 0;
        var first_cookie = true;
        for (decoded) |h| {
            if (!std.mem.eql(u8, h.name, "cookie")) continue;
            if (!first_cookie) {
                joined[pos] = ';';
                joined[pos + 1] = ' ';
                pos += 2;
            }
            first_cookie = false;
            @memcpy(joined[pos..][0..h.value.len], h.value);
            pos += h.value.len;
        }
        std.debug.assert(pos == cookie_total_len);
        hdrs.items[cookie_idx.?].value = joined;
    }

    if (!seen_method or !proto2.isValidToken(method)) return error.BadRequest;
    if (std.mem.eql(u8, method, "CONNECT")) return error.BadRequest;
    if (!seen_scheme or !proto2.isValidScheme(scheme)) return error.BadRequest;
    if (!seen_path or path.len == 0) return error.BadRequest;
    for (path) |ch| if (ch <= 0x20 or ch >= 0x7f) return error.BadRequest;

    const is_http_scheme = std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https");
    if (is_http_scheme) {
        const is_asterisk_options = std.mem.eql(u8, method, "OPTIONS") and std.mem.eql(u8, path, "*");
        if (path[0] != '/' and !is_asterisk_options) return error.BadRequest;
    }

    if (seen_authority) {
        if (authority.len == 0 and (is_http_scheme or host != null)) return error.BadRequest;
        for (authority) |ch| if (ch <= 0x20 or ch >= 0x7f or ch == '@') return error.BadRequest;
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
        st.done.store(true, .release); // one-way set, before the wakeup
        if (st.armed) {
            st.wake_event.set(conn.io); // wake the watchdog so it observes `done`
            // Must be uncancelable: if `wait` returned early due to cancellation,
            // the watchdog could still be touching `st`, and freeing it afterward
            // would be a use-after-free. Equivalent to the old `thread.join()`.
            st.watchdog_done.waitUncancelable(conn.io);
        }
        removeCompletedStream(conn, st);
        // Return connection-level credit for body bytes the handler never
        // consumed, and flush any remaining sub-threshold conn_recv_pending
        // credit so the peer regains the full connection window once this
        // stream completes. After removeCompletedStream the stream is
        // unreachable by the reader thread, so rx_buf is stable without rx_mu.
        const leftover: i64 = @intCast(st.rx_buf.len);
        if (!conn.closing.load(.acquire)) {
            const dc = creditConnEx(conn, leftover, true);
            if (dc > 0) sendWindowUpdate(conn, 0, dc);
        }
        st.rx_buf.deinit(conn.gpa);
        st.arena_state.deinit();
        conn.gpa.destroy(st);
        conn.workers_mu.lockUncancelable(conn.io);
        conn.active_workers -= 1;
        conn.workers_cond.broadcast(conn.io);
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
        if (st.timed_out.load(.acquire)) {
            if (!res.finished) rstStreamCode(conn, st.id, .cancel);
            return;
        }
        log.warn("h2 handler error: {t}", .{err});
        if (!res.finished) rstStreamCode(conn, st.id, .internal_error);
        return;
    };
    // Normal completion: ensure the response head + END_STREAM are emitted, or
    // RST_STREAM(CANCEL) if the deadline expired without the handler finishing
    // the response itself (e.g. via gRPC DEADLINE_EXCEEDED trailers).
    if (st.reset.load(.acquire) or conn.closing.load(.acquire)) return;
    if (st.timed_out.load(.acquire)) {
        if (!res.finished) rstStreamCode(conn, st.id, .cancel);
        return;
    }
    res.finish() catch |err| {
        if (!st.reset.load(.acquire) and !conn.closing.load(.acquire) and !res.finished) {
            log.warn("h2 response finish error: {t}", .{err});
            rstStreamCode(conn, st.id, .internal_error);
        }
    };
}

fn removeCompletedStream(conn: *Connection, st: *H2Stream) void {
    conn.streams_mu.lockUncancelable(conn.io);
    _ = conn.streams.remove(st.id);
    // After streams.remove, the reader can no longer deliver DATA/trailers to
    // `st`, so `rx_eof` is stable here.
    if (st.response_finished.load(.acquire) and !st.reset.load(.acquire) and !st.rx_eof) {
        conn.early_closed[conn.early_closed_pos] = st.id;
        conn.early_closed_pos = (conn.early_closed_pos + 1) % conn.early_closed.len;
    }
    conn.streams_mu.unlock(conn.io);
}

fn removeStream(conn: *Connection, sid: u31) void {
    conn.streams_mu.lockUncancelable(conn.io);
    _ = conn.streams.remove(sid);
    conn.streams_mu.unlock(conn.io);
}

fn rstStreamCode(conn: *Connection, sid: u31, code: ErrorCode) void {
    var p: [4]u8 = undefined;
    std.mem.writeInt(u32, &p, @backingInt(code), .big);
    conn.cw.frame(.rst_stream, 0, sid, &p) catch {};
}

/// Emits a single WINDOW_UPDATE frame (increment > 0). Best-effort; window
/// values are <= 2^31-1 so `incr` fits in the 31-bit field.
fn sendWindowUpdate(conn: *Connection, sid: u31, incr: i64) void {
    // Increment must fit the 31-bit WINDOW_UPDATE field; a single credit never
    // exceeds the connection/stream window, which is <= 2^31-1.
    std.debug.assert(incr > 0 and incr <= 0x7fff_ffff);
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, @intCast(incr & 0x7fff_ffff), .big);
    conn.cw.frame(.window_update, 0, sid, &wu) catch {};
}

/// Coalesces a stream-level and connection-level WINDOW_UPDATE into a single
/// writer lock acquisition and flush whenever both are non-zero.
fn sendWindowUpdates(conn: *Connection, sid: u31, stream_incr: i64, conn_incr: i64) void {
    if (stream_incr <= 0 and conn_incr <= 0) return;
    conn.cw.lock();
    defer conn.cw.unlock();
    if (conn.cw.broken) return;
    if (stream_incr > 0) {
        std.debug.assert(stream_incr <= 0x7fff_ffff);
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, @intCast(stream_incr & 0x7fff_ffff), .big);
        conn.cw.frameLocked(.window_update, 0, sid, &wu) catch {
            conn.cw.broken = true;
            return;
        };
    }
    if (conn_incr > 0) {
        std.debug.assert(conn_incr <= 0x7fff_ffff);
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, @intCast(conn_incr & 0x7fff_ffff), .big);
        conn.cw.frameLocked(.window_update, 0, 0, &wu) catch {
            conn.cw.broken = true;
            return;
        };
    }
    conn.cw.w.flush() catch {
        conn.cw.broken = true;
    };
}

/// Records `amt` connection-level consumed/returned bytes; returns the
/// stream-0 WINDOW_UPDATE increment to emit (0 if below half-window threshold).
/// Takes `recv_mu` itself — caller must NOT hold it.
fn creditConn(conn: *Connection, amt: i64) i64 {
    return creditConnEx(conn, amt, false);
}

/// Like `creditConn`; when `flush_all` is true (e.g. stream completion),
/// flushes all accumulated `conn_recv_pending > 0` regardless of threshold so
/// sub-threshold credit is never stranded on an idle connection.
fn creditConnEx(conn: *Connection, amt: i64, flush_all: bool) i64 {
    conn.recv_mu.lockUncancelable(conn.io);
    defer conn.recv_mu.unlock(conn.io);
    conn.conn_recv_pending += amt;
    if (conn.conn_recv_pending <= 0) return 0;
    const threshold = @max(@as(i64, 1), clampConnWindow(conn.srv.config.connection_window_size) >> 1);
    if (flush_all or conn.conn_recv_pending >= threshold) {
        const d = conn.conn_recv_pending;
        conn.conn_recv_window += d;
        conn.conn_recv_pending = 0;
        return d;
    }
    return 0;
}

const isConnectionSpecificHeader = proto2.isConnectionSpecificHeader;

// ---------------------------------------------------------------------------
// Tests. Transport-level tests talk raw h2 frames over a plain AF_UNIX
// socketpair — no TLS — so the suite is self-contained and dependency-free.
// ---------------------------------------------------------------------------

const testing = std.testing;

// 0.17 移除 @cImport。测试只用到 socketpair/close/AF_UNIX/SOCK_STREAM 四个 libc 符号，
// 映射到 std.c/std.posix。
const c = struct {
    const socketpair = std.c.socketpair;
    const close = std.c.close;
    const AF_UNIX = std.posix.AF.UNIX;
    const SOCK_STREAM = std.posix.SOCK.STREAM;
};

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

test "validateInboundFrame rejects RST_STREAM with the wrong length" {
    try testing.expectEqual(
        @as(?ErrorCode, .frame_size_error),
        validateInboundFrame(.{ .length = 5, .ftype = .rst_stream, .flags = 0, .sid = 1 }, &[_]u8{ 0, 0, 0, 0, 0 }),
    );
    // A correct 4-byte RST_STREAM is accepted.
    try testing.expectEqual(
        @as(?ErrorCode, null),
        validateInboundFrame(.{ .length = 4, .ftype = .rst_stream, .flags = 0, .sid = 1 }, &[_]u8{ 0, 0, 0, 0 }),
    );
}

test "validateInboundFrame rejects PRIORITY with the wrong length" {
    try testing.expectEqual(
        @as(?ErrorCode, .frame_size_error),
        validateInboundFrame(.{ .length = 4, .ftype = .priority, .flags = 0, .sid = 1 }, &[_]u8{ 0, 0, 0, 0 }),
    );
}

test "validateInboundFrame accepts normal client SETTINGS" {
    const payload = [_]u8{ 0, 4, 0, 0, 0xff, 0xff };
    try testing.expectEqual(
        @as(?ErrorCode, null),
        validateInboundFrame(.{ .length = payload.len, .ftype = .settings, .flags = 0, .sid = 0 }, &payload),
    );
}

test "buildRequest rejects a malformed content-length" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/upload" },
        .{ .name = "content-length", .value = "not-a-number" },
    };

    try testing.expectError(error.BadRequest, buildRequest(arena, &decoded));
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

var tighten_fired = std.atomic.Value(bool).init(false);
var extend_fired = std.atomic.Value(bool).init(false);

/// Sets a far deadline, then tightens it to a near one, then blocks reading
/// the body. A correct implementation must fire at the "nearer" deadline,
/// not wait for the original far one.
fn tightenDeadlineHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(10 * std.time.ns_per_s); // far
    ctx.setDeadlineIn(80 * std.time.ns_per_ms); // tighten to near
    if (ctx.body_reader) |br| {
        var tmp: [64]u8 = undefined;
        while (true) {
            const n = br.read(&tmp) catch |err| switch (err) {
                error.DeadlineExceeded => {
                    tighten_fired.store(true, .release);
                    return err;
                },
                else => return err,
            };
            if (n == 0) break;
        }
    }
    return error.TestUnexpectedResult;
}

/// Sets a near deadline, then extends it to a far one, then blocks reading
/// the body. A correct implementation must defer to the "farther" deadline:
/// it must not fire within the short window.
fn extendDeadlineHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(80 * std.time.ns_per_ms); // near
    ctx.setDeadlineIn(10 * std.time.ns_per_s); // extend to far
    if (ctx.body_reader) |br| {
        var tmp: [64]u8 = undefined;
        while (true) {
            const n = br.read(&tmp) catch |err| switch (err) {
                error.DeadlineExceeded => {
                    extend_fired.store(true, .release);
                    return err;
                },
                else => return err,
            };
            if (n == 0) break;
        }
    }
    return error.TestUnexpectedResult;
}

/// Sets a far deadline then finishes immediately — the watchdog must be
/// reclaimed promptly, not left idling until the deadline.
fn armLongDeadlineHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(10 * std.time.ns_per_s);
    try ctx.res.send(200, "text/plain", "ok");
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

    var ack = try readFrameOfType(testing.allocator, &reader.interface, .settings);
    defer ack.deinit(testing.allocator);
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
    // Coalesced Response.send attaches END_STREAM directly to the final DATA frame (#41).
    try testing.expectEqual(flag_end_stream, data.header.flags & flag_end_stream);
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
    try testing.expectEqual(@backingInt(ErrorCode.internal_error), std.mem.readInt(u32, rst.payload[0..4], .big));
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
    try testing.expectEqual(@backingInt(ErrorCode.enhance_your_calm), code);
}

test "h2: zero-length CONTINUATION flood is capped with GOAWAY ENHANCE_YOUR_CALM" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if the spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        // Short head timeout so, before the fix, the reader blocking on the next
        // (never-arriving) frame surfaces fast instead of after the 30s default.
        .config = .{ .head_timeout_ms = 1_000 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    try writeFrame(&writer.interface, .settings, 0, 0, "");

    // HEADERS without END_HEADERS, then a stream of *empty* CONTINUATION frames.
    // Each adds zero bytes, so max_header_block_bytes never trips; only a
    // frame-count cap stops them (CVE-2024-27316 class). Send well over the cap.
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, 0, 1, &req_block);
    var sent: usize = 0;
    while (sent < 400) : (sent += 1) {
        writeFrame(&writer.interface, .continuation, 0, 1, "") catch break;
    }

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expect(goaway.payload.len >= 8);
    try testing.expectEqual(@backingInt(ErrorCode.enhance_your_calm), std.mem.readInt(u32, goaway.payload[4..8], .big));
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
    try testing.expectEqual(@backingInt(ErrorCode.flow_control_error), std.mem.readInt(u32, goaway.payload[4..8], .big));
}

fn rapidResetFlood(w: *Io.Writer) void {
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    var sid: u31 = 1;
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        writeFrame(w, .headers, flag_end_headers | flag_end_stream, sid, &req_block) catch return;
        var code: [4]u8 = undefined;
        std.mem.writeInt(u32, &code, @backingInt(ErrorCode.cancel), .big);
        writeFrame(w, .rst_stream, 0, sid, &code) catch return;
        sid += 2;
    }
}

test "h2: rapid-reset flood (CVE-2023-44487) is cut off with GOAWAY ENHANCE_YOUR_CALM" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]); // reap the client end if a spawn below fails

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        // Short idle timeout so, before the fix, the drainer blocking after the
        // flood surfaces fast instead of after the 180s default.
        .config = .{ .idle_timeout_ms = 2_000 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });

    var rbuf: [4096]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    try writeFrame(&writer.interface, .settings, 0, 0, "");

    // Flood HEADERS→RST_STREAM pairs from a second thread while the main thread
    // drains responses, so the server's writes never block the connection.
    const sender = try std.Thread.spawn(.{}, rapidResetFlood, .{&writer.interface});
    // Teardown (LIFO): join the server (it closes its fd on return, which errors
    // the sender's in-flight write), then join the sender, then close our end.
    defer _ = c.close(fds[1]);
    defer sender.join();
    defer t.join();

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    try testing.expect(goaway.payload.len >= 8);
    const code = std.mem.readInt(u32, goaway.payload[4..8], .big);
    goaway.deinit(testing.allocator);
    try testing.expectEqual(@backingInt(ErrorCode.enhance_your_calm), code);

    // Drain until EOF: lets any worker blocked writing a response flush, so the
    // server can finish draining workers, return, and close its fd — which in
    // turn errors the sender's write so it (and the joins above) complete.
    while (true) {
        var f = readFrameAlloc(testing.allocator, &reader.interface) catch break;
        f.deinit(testing.allocator);
    }
}

test "h2: SETTINGS_MAX_FRAME_SIZE out of range is a connection PROTOCOL_ERROR" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        // Short idle timeout so, before the fix, the server closing on idle
        // surfaces as a fast EOF instead of hanging the test for 180s.
        .config = .{ .idle_timeout_ms = 1_000 },
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
    // SETTINGS_MAX_FRAME_SIZE = 0 is below the RFC 7540 §6.5.2 minimum (2^14);
    // values outside [16384, 16777215] MUST be a connection PROTOCOL_ERROR.
    // (0 also drove the DATA/HEADERS writers into a zero-length busy loop.)
    var s: [6]u8 = undefined;
    std.mem.writeInt(u16, s[0..2], set_max_frame_size, .big);
    std.mem.writeInt(u32, s[2..6], 0, .big);
    try writeFrame(&writer.interface, .settings, 0, 0, &s);

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expect(goaway.payload.len >= 8);
    try testing.expectEqual(@backingInt(ErrorCode.protocol_error), std.mem.readInt(u32, goaway.payload[4..8], .big));
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
    try writeFrame(&writer.interface, .goaway, 0, 0, &@as([8]u8, @splat(0)));

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
    try testing.expectEqual(@backingInt(ErrorCode.cancel), std.mem.readInt(u32, rst.payload[0..4], .big));
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

/// Shared body for the concurrent-streams tests: open a stream, send a body,
/// read the echo to end-of-stream, and bump `ok` if it round-tripped. `cli` is
/// `anytype` so this stays a module-level helper without importing client.zig
/// at module scope — the type resolves at each test's call site.
fn echoStreamWorker(cli: anytype, idx: usize, ok: *std.atomic.Value(u32)) void {
    var body_buf: [40]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "stream {d}", .{idx}) catch return;
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
            .headers => |h| if (h.end_stream) break,
            .rst, .goaway => return,
        }
    }
    if (std.mem.eql(u8, got.items, body)) {
        _ = ok.fetchAdd(1, .acq_rel);
        s.close();
    }
}

fn runConcurrentEchoStreams(comptime N: usize) !void {
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

    // Sized to comfortably hold N concurrent streams' frames.
    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    var client: client_mod.Client = undefined;
    try client.init(testing.io, testing.allocator, &reader.interface, &writer.interface);
    defer client.deinit(); // must stop the client reader before fds[1] closes

    var success = std.atomic.Value(u32).init(0);
    var threads: [N]std.Thread = undefined;
    for (0..N) |i| threads[i] = std.Thread.spawn(.{}, echoStreamWorker, .{ &client, i, &success }) catch return;
    for (threads) |th| th.join();
    try testing.expectEqual(@as(u32, N), success.load(.acquire));
}

test "h2 client: multiplexes concurrent streams over one connection" {
    try runConcurrentEchoStreams(4);
}

test "h2: server serves many concurrent streams via group workers and drains cleanly" {
    try runConcurrentEchoStreams(16);
}

test "h2: worker spawn falls back to a thread when the Io backend has no concurrency" {
    // A backend whose `concurrent`/`groupConcurrent` always return
    // ConcurrencyUnavailable, forcing spawnTask down its std.Thread fallback.
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();

    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{ .io = io, .gpa = testing.allocator, .handler = h2TestHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(io, &rbuf);
    var writer = peerStream(fds[1]).writer(io, &wbuf);
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
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);

    // The worker ran via the fallback thread, so the response still arrives.
    var resp = try readFrameOfType(testing.allocator, &reader.interface, .headers);
    defer resp.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var dec = hpack.Decoder.init(testing.allocator, our_header_table_size);
    defer dec.deinit();
    const hs = try dec.decode(arena.allocator(), resp.payload);
    try testing.expectEqualStrings("200", findHeaderValue(hs, ":status").?);
}

test "h2: tightening a deadline fires at the earlier time (no regression)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = tightenDeadlineHandler,
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
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    // No END_STREAM → the handler blocks on body_reader until the (tightened) deadline fires.
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);

    // The tightened deadline is 80ms; wait well past it but well below 10s.
    // If the implementation degenerates to only honoring the first (10s)
    // deadline, it will not have fired yet here → test fails.
    Io.sleep(testing.io, .{ .nanoseconds = 400 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(tighten_fired.load(.acquire));
}

test "h2: extending a deadline pushes the timeout later (no regression)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = extendDeadlineHandler,
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
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &req_block);

    // The extended deadline is 10s; wait well past the original 80ms but well
    // below 10s. A correct implementation must NOT have fired yet here (the
    // watchdog re-waits on the later deadline); if it degenerates to only
    // honoring the first (80ms) deadline, it will have fired already → fails.
    Io.sleep(testing.io, .{ .nanoseconds = 400 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(!extend_fired.load(.acquire));
}

test "h2: deadline watchdog is reclaimed promptly when the handler finishes early" {
    const fds = try newSocketPair();
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = armLongDeadlineHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });

    // `shut` guard: if any `try` fails, the defer performs close+join;
    // the success path closes+joins explicitly and sets it true first.
    var shut = false;
    defer if (!shut) {
        _ = c.close(fds[1]);
        t.join();
    };

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var settings = try readFrameAlloc(testing.allocator, &reader.interface);
    settings.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");
    // END_STREAM: no body, so the handler returns immediately.
    const req_block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);

    // Read the response's END_STREAM to confirm the handler has finished.
    var saw_end = false;
    while (!saw_end) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        defer f.deinit(testing.allocator);
        if ((f.header.flags & flag_end_stream) != 0 and
            (f.header.ftype == .data or f.header.ftype == .headers)) saw_end = true;
    }

    // Close the client side → server readLoop sees EOF → drainWorkers. Time the close+join.
    // If the watchdog can only sleep until the 10s deadline, the worker would be
    // stuck in its cleanup defer for ~10s, and join would be dragged along with it.
    const start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
    shut = true;
    _ = c.close(fds[1]);
    t.join();
    const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - start, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 2000);
}

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

test "h2 client: partial queue drain frees the remaining buffered items (q_head)" {
    // Guards the head-index dequeue: readEvent frees the items it consumes and
    // freeQueued frees only [q_head..]. If a stream is torn down while some items
    // were consumed and others are still buffered, there must be no double-free
    // (of consumed items) and no leak (of buffered ones) — testing.allocator
    // flags either.
    const client_mod = @import("client.zig");
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
    var client: client_mod.Client = undefined;
    try client.init(testing.io, testing.allocator, &reader.interface, &writer.interface);
    defer client.deinit(); // frees the partially-drained stream via freeQueued([q_head..])

    const s = try client.openStream(.{ .path = "/x", .method = "POST" }, false);
    try s.send("hello", true);
    // Let the whole response (HEADERS + DATA + END_STREAM) queue up, then read
    // only the first event so later items stay buffered (q_head > 0 at deinit).
    Io.sleep(testing.io, .{ .nanoseconds = 80 * std.time.ns_per_ms }, .awake) catch {};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    _ = try s.readEvent(arena.allocator());
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

    // The client's reader thread applies the server's advertised
    // SETTINGS_INITIAL_WINDOW_SIZE asynchronously; wait for it so `send`
    // below flow-controls against the real (small) window instead of racing
    // ahead with the client's default (65535) and tripping the new stream
    // overflow RST on a spurious over-large first DATA frame.
    var waited: usize = 0;
    while (client.peer_initial_window.load(.acquire) != srv.config.initial_window_size) : (waited += 1) {
        if (waited > 2000) return error.SettingsNotApplied;
        Io.sleep(testing.io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
    }

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

    // readFrameOfType only filters by frame type, and the connection-level
    // WINDOW_UPDATE (sid 0) is always emitted synchronously in handleData
    // before any stream-level credit, so skip sid-0 frames to find the
    // stream-level one this test is actually asserting on.
    var wu: TestFrame = while (true) {
        var f = try readFrameOfType(testing.allocator, &reader.interface, .window_update);
        if (f.header.sid != 0) break f;
        f.deinit(testing.allocator);
    };
    defer wu.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), wu.header.sid); // stream-level credit
    const incr = std.mem.readInt(u32, wu.payload[0..4], .big) & 0x7fff_ffff;
    try testing.expect(incr > 0);
}

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
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.flow_control_error)), std.mem.readInt(u32, rst.payload[0..4], .big));
}

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
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.flow_control_error)), std.mem.readInt(u32, goaway.payload[4..8], .big));
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
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, rst.payload[0..4], .big));
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
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, rst.payload[0..4], .big));
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
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.stream_closed)), std.mem.readInt(u32, rst.payload[0..4], .big));

    // Connection must stay alive for subsequent stream 3.
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, &trailers_req_block);
    var ok3 = false;
    while (true) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        const es = f.header.sid == 3 and f.header.flags & flag_end_stream != 0 and (f.header.ftype == .data or f.header.ftype == .headers);
        f.deinit(testing.allocator);
        if (es) {
            ok3 = true;
            break;
        }
    }
    try testing.expect(ok3);
}

/// Responds with the value of `x-marker`, or "MISSING" — a probe for whether a
/// header block decoded against the expected HPACK dynamic table.
fn markerHandler(ctx: *types.Context) anyerror!void {
    if (ctx.body_reader) |br| {
        var tmp: [64]u8 = undefined;
        while (true) {
            const n = try br.read(&tmp);
            if (n == 0) break;
        }
    }
    try ctx.res.send(200, "text/plain", ctx.req.get("x-marker") orelse "MISSING");
}

test "h2: a stream refused at max_concurrent_streams still advances the HPACK decoder" {
    // HPACK's dynamic table is connection state built from every block in wire
    // order, whether or not we serve the stream. Refusing without decoding left
    // our table one entry behind the peer's, and every later indexed reference
    // on the connection silently resolved to the wrong field.
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = markerHandler,
        .config = .{ .max_concurrent_streams = 1, .idle_timeout_ms = 5_000 },
    };
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

    // Stream 1: no END_STREAM, so its handler blocks on the body and the stream
    // holds the connection's only concurrency slot.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);

    // Stream 3: refused for lack of a slot. Its block carries a literal with
    // incremental indexing, so a correctly-synced decoder gains dynamic entry
    // 62 = (x-marker, zzz) even though nothing serves the stream.
    const marker_block = [_]u8{ 0x82, 0x86, 0x84, 0x40, 0x08 } ++ "x-marker".* ++ [_]u8{0x03} ++ "zzz".*;
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, &marker_block);
    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 3), rst.header.sid);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.refused_stream)), std.mem.readInt(u32, rst.payload[0..4], .big));

    // Free the slot by ending stream 1, then drain its response.
    try writeFrame(&writer.interface, .data, flag_end_stream, 1, "");
    while (true) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        const es = (f.header.ftype == .data or f.header.ftype == .headers) and f.header.flags & flag_end_stream != 0;
        f.deinit(testing.allocator);
        if (es) break;
    }

    // Stream 5 references dynamic index 62. In sync that is (x-marker, zzz);
    // with the refused block skipped it is stream 1's (:authority, ...) and the
    // handler sees no marker at all.
    const indexed_block = [_]u8{ 0x82, 0x86, 0x84, 0x80 | 62 };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 5, &indexed_block);
    var data = try readFrameWith(testing.allocator, &reader.interface, .data, 5);
    defer data.deinit(testing.allocator);
    try testing.expectEqualStrings("zzz", data.payload);
}

test "h2: HEADERS whose padding exceeds the payload is a connection PROTOCOL_ERROR" {
    // Previously a bare `return`: no response on the stream (the peer waits
    // forever) and the block was never decoded, desyncing HPACK.
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2TestHandler,
        .config = .{ .idle_timeout_ms = 2_000 },
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

    // PADDED with a pad length of 200 over a 21-byte payload.
    const padded = [_]u8{200} ++ trailers_req_block;
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream | flag_padded, 1, &padded);

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, goaway.payload[4..8], .big));
}

test "buildRequest rejects an uppercase field name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/x" },
        .{ .name = "X-Smuggled", .value = "1" }, // malformed: RFC 9113 §8.2.1
    };

    try testing.expectError(error.BadRequest, buildRequest(arena_state.allocator(), &decoded));
}

test "h2: a client-sent PUSH_PROMISE is a connection PROTOCOL_ERROR" {
    // RFC 9113 §6.6: a client cannot push (and we advertise ENABLE_PUSH=0).
    // The frame also carries a header-block fragment: dropping it silently
    // leaves our HPACK table one block behind the peer's.
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = markerHandler,
        .config = .{ .idle_timeout_ms = 2_000 },
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

    // PUSH_PROMISE (promised stream 2) carrying a one-byte block fragment.
    var pp: [5]u8 = undefined;
    std.mem.writeInt(u32, pp[0..4], 2, .big);
    pp[4] = 0x88; // indexed-field: :status 200
    try writeFrame(&writer.interface, .push_promise, flag_end_headers, 0, &pp);

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, goaway.payload[4..8], .big));
}

test "h2: DATA on an idle stream is a connection PROTOCOL_ERROR" {
    // DATA on an id we never opened was silently dropped (window credited
    // back, no error), letting a peer stream garbage on idle ids forever.
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = markerHandler,
        .config = .{ .idle_timeout_ms = 2_000 },
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

    // No stream was ever opened: sid 1 is idle.
    try writeFrame(&writer.interface, .data, 0, 1, "xxxx");

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, goaway.payload[4..8], .big));
}

test "h2: DATA on a closed stream gets RST(STREAM_CLOSED) and keeps the connection" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = markerHandler,
        .config = .{ .idle_timeout_ms = 5_000 },
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

    // Complete stream 1 (bodyless GET) and drain its response to END_STREAM.
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
    while (true) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        const es = (f.header.ftype == .data or f.header.ftype == .headers) and f.header.flags & flag_end_stream != 0;
        f.deinit(testing.allocator);
        if (es) break;
    }

    // DATA on the now-closed stream: a stream error, not a connection one.
    try writeFrame(&writer.interface, .data, 0, 1, "xxxx");
    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.stream_closed)), std.mem.readInt(u32, rst.payload[0..4], .big));
}

test "h2: SETTINGS_INITIAL_WINDOW_SIZE that overflows a stream window is a connection FLOW_CONTROL_ERROR" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = markerHandler,
        .config = .{ .idle_timeout_ms = 5_000 },
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

    // Keep stream 1 open: no END_STREAM, so its handler blocks reading the body.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    // Push stream 1's send window to exactly 2^31-1, then raise the initial
    // window by one: the delta shifts every open stream past the ceiling
    // (RFC 7540 §6.9.2).
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, 0x7fff_ffff - 65535, .big);
    try writeFrame(&writer.interface, .window_update, 0, 1, &wu);
    var iw: [6]u8 = undefined;
    putSetting(&iw, set_initial_window_size, 65536);
    try writeFrame(&writer.interface, .settings, 0, 0, &iw);

    var goaway = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer goaway.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.flow_control_error)), std.mem.readInt(u32, goaway.payload[4..8], .big));
}

test "buildRequest rejects conflicting duplicate content-length" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/x" },
        .{ .name = "content-length", .value = "7" },
        .{ .name = "content-length", .value = "8" }, // differs: smuggling
    };

    try testing.expectError(error.BadRequest, buildRequest(arena_state.allocator(), &decoded));
}

test "buildRequest accepts identical duplicate content-length" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const decoded = [_]hpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/x" },
        .{ .name = "content-length", .value = "7" },
        .{ .name = "content-length", .value = "7" },
    };

    const req = try buildRequest(arena_state.allocator(), &decoded);
    try testing.expectEqual(@as(u64, 7), req.content_length.?);
    // The duplicate is deduplicated on the wire field list too: forwarding
    // both copies invites a size-confusion on any downstream hop.
    try testing.expectEqual(@as(usize, 1), countHeaders(req.headers, "content-length"));
}

test "buildRequest rejects CTL octets in field names and values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const base = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/x" },
    };
    {
        var decoded = base ++ [_]hpack.Header{.{ .name = "x-bad", .value = "a\r\nb" }};
        try testing.expectError(error.BadRequest, buildRequest(arena_state.allocator(), &decoded));
    }
    {
        var decoded = base ++ [_]hpack.Header{.{ .name = "x-ba\x00d", .value = "ok" }};
        try testing.expectError(error.BadRequest, buildRequest(arena_state.allocator(), &decoded));
    }
    // Pseudo-header values are scanned too: CRLF in :path is the same
    // injection primitive against an HTTP/1 hop.
    {
        var decoded = base ++ [_]hpack.Header{.{ .name = ":path", .value = "/x\r\nGET / HTTP/1.1" }};
        try testing.expectError(error.BadRequest, buildRequest(arena_state.allocator(), &decoded));
    }
}

fn nextFrameWithin(a: std.mem.Allocator, r: *Io.Reader, fd: c_int, ms: i32) !?TestFrame {
    if (r.bufferedLen() == 0) {
        var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        if ((try std.posix.poll(&pfd, ms)) == 0) return null;
    }
    return try readFrameAlloc(a, r);
}

fn rawHandshake(reader: *Io.Reader, writer: *Io.Writer) !void {
    try writer.writeAll(preface);
    try writer.flush();
    var settings = try readFrameAlloc(testing.allocator, reader);
    settings.deinit(testing.allocator);
    try writeFrame(writer, .settings, 0, 0, "");
    try writeFrame(writer, .settings, flag_ack, 0, "");
}

fn deadlinePropagateHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(60 * std.time.ns_per_ms);
    var tmp: [64]u8 = undefined;
    _ = try ctx.body_reader.?.read(&tmp);
}

fn deadlineSwallowHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(60 * std.time.ns_per_ms);
    var tmp: [64]u8 = undefined;
    _ = ctx.body_reader.?.read(&tmp) catch return;
}

fn deadlineTrailersHandler(ctx: *types.Context) anyerror!void {
    ctx.setDeadlineIn(60 * std.time.ns_per_ms);
    var tmp: [64]u8 = undefined;
    _ = ctx.body_reader.?.read(&tmp) catch |err| {
        if (err == error.DeadlineExceeded) {
            ctx.res.status(200);
            try ctx.res.trailer("grpc-status", "4");
            try ctx.res.finish();
            return;
        }
        return err;
    };
}

test "h2: expired per-RPC deadline closes the stream with RST_STREAM(CANCEL) (#16)" {
    inline for (.{ deadlinePropagateHandler, deadlineSwallowHandler }) |h| {
        const fds = try newSocketPair();
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = h, .config = .{} };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);

        var rst_code: ?u32 = null;
        for (0..20) |_| {
            const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
            var f = maybe orelse continue;
            defer f.deinit(testing.allocator);
            if (f.header.sid == 1 and f.header.ftype == .rst_stream) {
                rst_code = std.mem.readInt(u32, f.payload[0..4], .big);
                break;
            }
        }
        try testing.expectEqual(@as(?u32, @backingInt(ErrorCode.cancel)), rst_code);
    }
}

test "h2: handler catching DeadlineExceeded can still finish with trailers (#16)" {
    const fds = try newSocketPair();
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = deadlineTrailersHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);

    var saw_end_headers = false;
    var saw_rst = false;
    for (0..20) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 50) catch break;
        var f = maybe orelse {
            if (saw_end_headers) break;
            continue;
        };
        defer f.deinit(testing.allocator);
        if (f.header.sid != 1) continue;
        if (f.header.ftype == .headers and f.header.flags & flag_end_stream != 0) saw_end_headers = true;
        if (f.header.ftype == .rst_stream) saw_rst = true;
    }
    try testing.expect(saw_end_headers);
    try testing.expect(!saw_rst);
}

fn goawayWaitReadHandler(ctx: *types.Context) anyerror!void {
    Io.sleep(ctx.io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .awake) catch {};
    var buf: [64]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = try ctx.body_reader.?.read(buf[total..]);
        if (n == 0) break;
        total += n;
    }
    try ctx.res.send(200, "text/plain", buf[0..total]);
}

fn goawayWaitWriteHandler(ctx: *types.Context) anyerror!void {
    Io.sleep(ctx.io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .awake) catch {};
    try ctx.res.send(200, "text/plain", "pong");
}

fn runGracefulGoawayCase(comptime with_body: bool) !void {
    const fds = try newSocketPair();
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = if (with_body) goawayWaitReadHandler else goawayWaitWriteHandler,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    if (with_body) {
        try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
        try writeFrame(&writer.interface, .data, flag_end_stream, 1, "hello");
    } else {
        try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
    }
    var goaway: [8]u8 = @splat(0);
    std.mem.writeInt(u32, goaway[0..4], 1, .big); // NO_ERROR
    try writeFrame(&writer.interface, .goaway, 0, 0, &goaway);

    var body: [64]u8 = undefined;
    var body_len: usize = 0;
    var ended = false;
    for (0..30) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
        var f = maybe orelse continue;
        defer f.deinit(testing.allocator);
        if (f.header.ftype != .data or f.header.sid != 1) continue;
        @memcpy(body[body_len..][0..f.payload.len], f.payload);
        body_len += f.payload.len;
        if (f.header.flags & flag_end_stream != 0) {
            ended = true;
            break;
        }
    }
    try testing.expect(ended);
    try testing.expectEqualStrings(if (with_body) "hello" else "pong", body[0..body_len]);
}

test "h2: peer graceful GOAWAY drains in-flight stream with buffered body (#17)" {
    try runGracefulGoawayCase(true);
}

test "h2: peer graceful GOAWAY drains in-flight bodyless stream (#17)" {
    try runGracefulGoawayCase(false);
}

var stop_case_started = std.atomic.Value(bool).init(false);

fn stopDrainHandler(ctx: *types.Context) anyerror!void {
    stop_case_started.store(true, .release);
    Io.sleep(ctx.io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .awake) catch {};
    try ctx.res.send(200, "text/plain", "pong");
}

test "h2: Server.stop drains in-flight stream instead of aborting it (#17)" {
    stop_case_started.store(false, .release);
    const fds = try newSocketPair();
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = stopDrainHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);

    var spins: u32 = 0;
    while (!stop_case_started.load(.acquire) and spins < 2000) : (spins += 1) {
        Io.sleep(testing.io, .{ .nanoseconds = std.time.ns_per_ms }, .awake) catch {};
    }
    try testing.expect(stop_case_started.load(.acquire));
    srv.stop.store(true, .release);
    try writeFrame(&writer.interface, .ping, 0, 0, &@as([8]u8, @splat(0)));

    var body: [64]u8 = undefined;
    var body_len: usize = 0;
    var ended = false;
    var saw_goaway = false;
    for (0..30) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
        var f = maybe orelse continue;
        defer f.deinit(testing.allocator);
        if (f.header.ftype == .goaway) {
            try testing.expectEqual(@as(u32, @backingInt(ErrorCode.no_error)), std.mem.readInt(u32, f.payload[4..8], .big));
            saw_goaway = true;
        }
        if (f.header.ftype == .data and f.header.sid == 1) {
            @memcpy(body[body_len..][0..f.payload.len], f.payload);
            body_len += f.payload.len;
            if (f.header.flags & flag_end_stream != 0) ended = true;
        }
        if (ended and saw_goaway) break;
    }
    try testing.expect(saw_goaway);
    try testing.expect(ended);
    try testing.expectEqualStrings("pong", body[0..body_len]);
}

test "h2: graceful GOAWAY delivers remaining body DATA and refuses new streams (#17)" {
    const fds = try newSocketPair();
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = h2EchoHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Open stream 1 without END_STREAM, then send graceful GOAWAY(NO_ERROR).
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    var goaway: [8]u8 = @splat(0);
    try writeFrame(&writer.interface, .goaway, 0, 0, &goaway);
    // A new stream opened while draining must be refused.
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, &trailers_req_block);
    // Stream 1's remaining body arrives after GOAWAY and must still complete.
    try writeFrame(&writer.interface, .data, flag_end_stream, 1, "late-body");

    var body: [64]u8 = undefined;
    var body_len: usize = 0;
    var ended = false;
    var refused_sid3 = false;
    for (0..30) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
        var f = maybe orelse continue;
        defer f.deinit(testing.allocator);
        if (f.header.ftype == .rst_stream and f.header.sid == 3) {
            try testing.expectEqual(@as(u32, @backingInt(ErrorCode.refused_stream)), std.mem.readInt(u32, f.payload[0..4], .big));
            refused_sid3 = true;
        }
        if (f.header.ftype == .data and f.header.sid == 1) {
            @memcpy(body[body_len..][0..f.payload.len], f.payload);
            body_len += f.payload.len;
            if (f.header.flags & flag_end_stream != 0) ended = true;
        }
        if (ended and refused_sid3) break;
    }
    try testing.expect(refused_sid3);
    try testing.expect(ended);
    try testing.expectEqualStrings("late-body", body[0..body_len]);
}

var fatal_goaway_err: ?anyerror = null;

fn fatalGoawayBlockedReadHandler(ctx: *types.Context) anyerror!void {
    var buf: [64]u8 = undefined;
    _ = ctx.body_reader.?.read(&buf) catch |err| {
        fatal_goaway_err = err;
        return;
    };
}

test "h2: fatal peer GOAWAY aborts blocked workers immediately (#17)" {
    fatal_goaway_err = null;
    const fds = try newSocketPair();
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = fatalGoawayBlockedReadHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Stream 1 blocks in body_reader.read() forever unless aborted.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    var goaway: [8]u8 = @splat(0);
    std.mem.writeInt(u32, goaway[4..8], @backingInt(ErrorCode.protocol_error), .big);
    try writeFrame(&writer.interface, .goaway, 0, 0, &goaway);

    // Server thread must exit promptly even before the peer closes its socket.
    t.join();
    _ = c.close(fds[1]);
    try testing.expectEqual(@as(?anyerror, error.StreamReset), fatal_goaway_err);
}

fn slowOkHandler(ctx: *types.Context) anyerror!void {
    Io.sleep(ctx.io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .awake) catch {};
    try ctx.res.send(200, "text/plain", "ok");
}

test "h2: DATA on a half-closed(remote) stream gets RST_STREAM(STREAM_CLOSED) (#20)" {
    const fds = try newSocketPair();
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = slowOkHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Bodyless GET: stream 1 is half-closed(remote) while its handler is running.
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
    try writeFrame(&writer.interface, .data, 0, 1, "junk");

    // Stream 3: body ended by DATA(END_STREAM), then followed by more DATA while running.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 3, &trailers_req_block);
    try writeFrame(&writer.interface, .data, flag_end_stream, 3, "legit");
    try writeFrame(&writer.interface, .data, 0, 3, "extra");

    // Stream 5: valid request proving the connection survives both stream errors.
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 5, &trailers_req_block);

    var rst1: ?u32 = null;
    var rst3: ?u32 = null;
    var ok5 = false;
    var post_rst_frame = false;
    for (0..40) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
        var f = maybe orelse continue;
        defer f.deinit(testing.allocator);
        if (f.header.ftype == .rst_stream and f.header.sid == 1) {
            rst1 = std.mem.readInt(u32, f.payload[0..4], .big);
        } else if (f.header.ftype == .rst_stream and f.header.sid == 3) {
            rst3 = std.mem.readInt(u32, f.payload[0..4], .big);
        } else if ((f.header.sid == 1 and rst1 != null) or (f.header.sid == 3 and rst3 != null)) {
            post_rst_frame = true;
        }
        if (f.header.ftype == .data and f.header.sid == 5 and f.header.flags & flag_end_stream != 0) {
            ok5 = true;
        }
        if (rst1 != null and rst3 != null and ok5) break;
    }
    try testing.expectEqual(@as(?u32, @backingInt(ErrorCode.stream_closed)), rst1);
    try testing.expectEqual(@as(?u32, @backingInt(ErrorCode.stream_closed)), rst3);
    try testing.expect(ok5);
    // Neither stream 1 nor stream 3 may emit HEADERS/DATA after its RST_STREAM.
    try testing.expect(!post_rst_frame);
}

test "h2: graceful GOAWAY does not abort a handler that outlives idle_timeout_ms (#17)" {
    const fds = try newSocketPair();
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = goawayWaitWriteHandler, // sleeps 150 ms before responding
        .config = .{ .idle_timeout_ms = 40 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
    var goaway: [8]u8 = @splat(0);
    std.mem.writeInt(u32, goaway[0..4], 1, .big); // NO_ERROR
    try writeFrame(&writer.interface, .goaway, 0, 0, &goaway);

    var body: [64]u8 = undefined;
    var body_len: usize = 0;
    var ended = false;
    for (0..30) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
        var f = maybe orelse continue;
        defer f.deinit(testing.allocator);
        if (f.header.ftype != .data or f.header.sid != 1) continue;
        @memcpy(body[body_len..][0..f.payload.len], f.payload);
        body_len += f.payload.len;
        if (f.header.flags & flag_end_stream != 0) {
            ended = true;
            break;
        }
    }
    try testing.expect(ended);
    try testing.expectEqualStrings("pong", body[0..body_len]);
}

test "h2: graceful GOAWAY drain works under ConcurrencyUnavailable fallback (#17)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();

    const fds = try newSocketPair();
    var srv: Server = .{ .io = io, .gpa = testing.allocator, .handler = h2EchoHandler, .config = .{} };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(io, &rbuf);
    var writer = peerStream(fds[1]).writer(io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Open stream 1 without END_STREAM, send graceful GOAWAY, then send the body:
    // readDrainHeader's synchronous fallback must keep reading DATA instead of
    // handing off to drainWorkers(true) and hanging the blocked worker.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    var goaway: [8]u8 = @splat(0);
    try writeFrame(&writer.interface, .goaway, 0, 0, &goaway);
    try writeFrame(&writer.interface, .data, flag_end_stream, 1, "sync-body");

    var body: [64]u8 = undefined;
    var body_len: usize = 0;
    var ended = false;
    for (0..30) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
        var f = maybe orelse continue;
        defer f.deinit(testing.allocator);
        if (f.header.ftype != .data or f.header.sid != 1) continue;
        @memcpy(body[body_len..][0..f.payload.len], f.payload);
        body_len += f.payload.len;
        if (f.header.flags & flag_end_stream != 0) {
            ended = true;
            break;
        }
    }
    try testing.expect(ended);
    try testing.expectEqualStrings("sync-body", body[0..body_len]);
}

test "Response.finish leaves finished false if sink.finish fails (#16)" {
    const FailingSink = struct {
        fn sendHead(_: *anyopaque, _: *types.Response) anyerror!void {}
        fn writeBody(_: *anyopaque, _: *types.Response, _: []const u8) anyerror!void {}
        fn finish(_: *anyopaque, _: *types.Response) anyerror!void {
            return error.OutOfMemory;
        }
        const vtable: types.Sink.Vtable = .{ .sendHead = sendHead, .writeBody = writeBody, .finish = finish };
    };
    var dummy: u8 = 0;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var res: types.Response = .{
        .arena = arena_state.allocator(),
        .sink = .{ .ctx = &dummy, .vtable = &FailingSink.vtable },
        .minor_version = 0,
    };
    try testing.expectError(error.OutOfMemory, res.finish());
    try testing.expect(res.head_sent);
    try testing.expect(!res.finished);
}

test "buildRequest rejects duplicate host headers and invalid field names (#23)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Duplicate host headers: second matches :authority while first differs.
    const dup_host = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "evil.example" },
        .{ .name = "host", .value = "victim.example" },
        .{ .name = "host", .value = "evil.example" },
    };
    try testing.expectError(error.BadRequest, buildRequest(arena, &dup_host));

    // Empty field name (RFC 9113 §8.2.1).
    const empty_name = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "", .value = "val" },
    };
    try testing.expectError(error.BadRequest, buildRequest(arena, &empty_name));

    // Regular field names containing colon, space, or DEL (0x7f).
    const bad_names = [_][]const u8{ "foo:bar", "foo bar", "foo\x7fbar" };
    for (bad_names) |bad| {
        const hs = [_]hpack.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = bad, .value = "val" },
        };
        try testing.expectError(error.BadRequest, buildRequest(arena, &hs));
    }
}

test "h2: content-length mismatch with DATA resets stream with PROTOCOL_ERROR (#23)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = markerHandler,
        .config = .{ .idle_timeout_ms = 5_000 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var cl5_block: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeRequest(
        arena_state.allocator(),
        &cl5_block,
        "POST",
        "https",
        "/upload",
        "example.com",
        &.{.{ .name = "content-length", .value = "5" }},
    );

    // Stream 1: bodyless HEADERS(END_STREAM) with content-length: 5 -> RST(PROTOCOL_ERROR).
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, cl5_block.items);
    // Stream 3: DATA exceeds content-length (6 > 5) -> RST(PROTOCOL_ERROR).
    try writeFrame(&writer.interface, .headers, flag_end_headers, 3, cl5_block.items);
    try writeFrame(&writer.interface, .data, flag_end_stream, 3, "123456");
    // Stream 5: DATA shorter than content-length at END_STREAM (3 < 5) -> RST(PROTOCOL_ERROR).
    try writeFrame(&writer.interface, .headers, flag_end_headers, 5, cl5_block.items);
    try writeFrame(&writer.interface, .data, flag_end_stream, 5, "123");
    // Stream 7: exact match (5 == 5) succeeds.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 7, cl5_block.items);
    try writeFrame(&writer.interface, .data, flag_end_stream, 7, "12345");

    var rst1: ?u32 = null;
    var rst3: ?u32 = null;
    var rst5: ?u32 = null;
    var ok7 = false;
    for (0..40) |_| {
        const maybe = nextFrameWithin(testing.allocator, &reader.interface, fds[1], 100) catch break;
        var f = maybe orelse continue;
        defer f.deinit(testing.allocator);
        if (f.header.ftype == .rst_stream) {
            const code = std.mem.readInt(u32, f.payload[0..4], .big);
            if (f.header.sid == 1) rst1 = code;
            if (f.header.sid == 3) rst3 = code;
            if (f.header.sid == 5) rst5 = code;
        } else if (f.header.sid == 7 and f.header.flags & flag_end_stream != 0) {
            ok7 = true;
        }
        if (rst1 != null and rst3 != null and rst5 != null and ok7) break;
    }
    try testing.expectEqual(@as(?u32, @backingInt(ErrorCode.protocol_error)), rst1);
    try testing.expectEqual(@as(?u32, @backingInt(ErrorCode.protocol_error)), rst3);
    try testing.expectEqual(@as(?u32, @backingInt(ErrorCode.protocol_error)), rst5);
    try testing.expect(ok7);
}

fn blockingReadHandler(ctx: *types.Context) anyerror!void {
    const flag: *std.atomic.Value(bool) = @ptrCast(@alignCast(ctx.userdata.?));
    var tmp: [64]u8 = undefined;
    _ = ctx.body_reader.?.read(&tmp) catch |err| {
        if (err == error.StreamReset) flag.store(true, .release);
        return err;
    };
}

test "h2: stream WINDOW_UPDATE overflow wakes handler blocked in body_reader.read (#23)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var woke_with_reset = std.atomic.Value(bool).init(false);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = blockingReadHandler,
        .userdata = &woke_with_reset,
        .config = .{ .idle_timeout_ms = 5_000 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Open stream 1 with body (no END_STREAM) so handler blocks in body_reader.read.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    Io.sleep(testing.io, .{ .nanoseconds = 30 * std.time.ns_per_ms }, .awake) catch {};

    // Overflow stream 1's send window: server must RST(FLOW_CONTROL_ERROR) and wake rx_cond.
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, 0x7fff_ffff, .big);
    try writeFrame(&writer.interface, .window_update, 0, 1, &wu);

    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst.header.sid);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.flow_control_error)), std.mem.readInt(u32, rst.payload[0..4], .big));

    // Graceful GOAWAY must drain promptly because the blocked worker woke up.
    var ga: [8]u8 = undefined;
    std.mem.writeInt(u32, ga[0..4], 1, .big);
    std.mem.writeInt(u32, ga[4..8], @backingInt(ErrorCode.no_error), .big);
    try writeFrame(&writer.interface, .goaway, 0, 0, &ga);

    var waited: u64 = 0;
    while (waited < 2000 and !woke_with_reset.load(.acquire)) : (waited += 20) {
        Io.sleep(testing.io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    }
    try testing.expect(woke_with_reset.load(.acquire));
}

test "h2: idle RST_STREAM, WINDOW_UPDATE, even DATA, bad ENABLE_PUSH, non-SETTINGS preface, and bad HPACK (#23)" {
    // 1. First frame after preface is PING instead of SETTINGS -> GOAWAY(PROTOCOL_ERROR).
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = markerHandler };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try writer.interface.writeAll(preface);
        const ping = @as([8]u8, @splat(0));
        try writeFrame(&writer.interface, .ping, 0, 0, &ping);
        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, ga.payload[4..8], .big));
    }

    // 2. SETTINGS_ENABLE_PUSH = 2 -> GOAWAY(PROTOCOL_ERROR).
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = markerHandler };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try writer.interface.writeAll(preface);
        var bad_push: [6]u8 = undefined;
        putSetting(&bad_push, set_enable_push, 2);
        try writeFrame(&writer.interface, .settings, 0, 0, &bad_push);
        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, ga.payload[4..8], .big));
    }

    // 3. RST_STREAM on idle stream -> GOAWAY(PROTOCOL_ERROR).
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = markerHandler };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        var rst: [4]u8 = undefined;
        std.mem.writeInt(u32, &rst, @backingInt(ErrorCode.cancel), .big);
        try writeFrame(&writer.interface, .rst_stream, 0, 99, &rst);
        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, ga.payload[4..8], .big));
    }

    // 4. WINDOW_UPDATE on idle stream -> GOAWAY(PROTOCOL_ERROR).
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = markerHandler };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, 100, .big);
        try writeFrame(&writer.interface, .window_update, 0, 99, &wu);
        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, ga.payload[4..8], .big));
    }

    // 5. DATA on even stream 2 after stream 3 opened -> GOAWAY(PROTOCOL_ERROR).
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = markerHandler };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, &trailers_req_block);
        try writeFrame(&writer.interface, .data, flag_end_stream, 2, "x");
        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @backingInt(ErrorCode.protocol_error)), std.mem.readInt(u32, ga.payload[4..8], .big));
    }

    // 6. Malformed HPACK block -> GOAWAY(COMPRESSION_ERROR) (RFC 9113 §4.3).
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = markerHandler };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        const bad_hpack = [_]u8{ 0x82, 0x20 }; // mid-block dynamic table size update
        try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &bad_hpack);
        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @backingInt(ErrorCode.compression_error)), std.mem.readInt(u32, ga.payload[4..8], .big));
    }

    // 7. Single oversized HEADERS(END_HEADERS) respects max_header_block_bytes.
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = markerHandler,
            .config = .{ .max_frame_size = 512 * 1024 },
        };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        const huge = try testing.allocator.alloc(u8, max_header_block_bytes + 1);
        defer testing.allocator.free(huge);
        @memset(huge, 0x20);
        writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, huge) catch {};
        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @backingInt(ErrorCode.enhance_your_calm)), std.mem.readInt(u32, ga.payload[4..8], .big));
    }
}

fn earlyRespondHandler(ctx: *types.Context) anyerror!void {
    try ctx.res.send(200, "text/plain", "early");
}

test "h2: in-flight DATA and trailers after early response keep connection alive and HPACK in sync (#23)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = earlyRespondHandler,
        .config = .{ .idle_timeout_ms = 5_000 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Stream 1: request with body (no END_STREAM); server replies immediately without reading body.
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &trailers_req_block);
    while (true) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        const es = f.header.sid == 1 and f.header.flags & flag_end_stream != 0 and (f.header.ftype == .data or f.header.ftype == .headers);
        f.deinit(testing.allocator);
        if (es) break;
    }

    // Wait briefly so worker removes stream 1, then send in-flight DATA + trailers (with incremental indexing).
    Io.sleep(testing.io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    try writeFrame(&writer.interface, .data, 0, 1, "in-flight-body");
    // Literal with incremental indexing: "x-trailer": "v" -> becomes dynamic index 62,
    // shifting stream 1's ":authority: www.example.com" to dynamic index 63.
    const trailer_block = [_]u8{ 0x40, 9, 'x', '-', 't', 'r', 'a', 'i', 'l', 'e', 'r', 1, 'v' };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailer_block);

    // Subsequent stream 3 uses dynamic index 63 (:authority) and 62 (x-trailer).
    // If the trailer block was NOT HPACK-decoded, index 63 would be out-of-range
    // (COMPRESSION_ERROR); if closed-stream HEADERS GOAWAY'd, stream 3 would fail.
    const req3 = [_]u8{ 0x82, 0x86, 0x84, 0x80 | 63, 0x80 | 62 };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, &req3);

    var ok3 = false;
    for (0..30) |_| {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        defer f.deinit(testing.allocator);
        try testing.expect(f.header.ftype != .goaway);
        if (f.header.sid == 3 and f.header.flags & flag_end_stream != 0 and (f.header.ftype == .data or f.header.ftype == .headers)) {
            ok3 = true;
            break;
        }
    }
    try testing.expect(ok3);
}

test "h2: duplicate RST_STREAM on early-answered streams is one-shot and still trips ENHANCE_YOUR_CALM (#23)" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = earlyRespondHandler,
        .config = .{ .idle_timeout_ms = 5_000 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    var rst_payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &rst_payload, @backingInt(ErrorCode.cancel), .big);

    var saw_goaway: ?u32 = null;
    for (1..121) |i| {
        const sid: u31 = @intCast(2 * i - 1);
        writeFrame(&writer.interface, .headers, flag_end_headers, sid, &trailers_req_block) catch break;
        while (true) {
            var f = readFrameAlloc(testing.allocator, &reader.interface) catch break;
            const go = f.header.ftype == .goaway;
            if (go) saw_goaway = std.mem.readInt(u32, f.payload[4..8], .big);
            const es = f.header.sid == sid and f.header.flags & flag_end_stream != 0 and
                (f.header.ftype == .data or f.header.ftype == .headers);
            f.deinit(testing.allocator);
            if (go or es) break;
        }
        if (saw_goaway != null) break;
        // First RST_STREAM is excused (one-shot); duplicate must still be counted.
        writeFrame(&writer.interface, .rst_stream, 0, sid, &rst_payload) catch break;
        writeFrame(&writer.interface, .rst_stream, 0, sid, &rst_payload) catch break;
    }
    if (saw_goaway == null) {
        if (readFrameOfType(testing.allocator, &reader.interface, .goaway)) |ga| {
            var g = ga;
            defer g.deinit(testing.allocator);
            saw_goaway = std.mem.readInt(u32, g.payload[4..8], .big);
        } else |_| {}
    }
    try testing.expectEqual(@as(?u32, @backingInt(ErrorCode.enhance_your_calm)), saw_goaway);
}

test "buildRequest joins multiple cookie fields and enforces RFC 9113 §8.2/§8.3 syntax" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cookies_ok = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/items" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "cookie", .value = "a=1" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "cookie", .value = "b=2" },
        .{ .name = "cookie", .value = "c=3" },
    };
    const req = try buildRequest(arena, &cookies_ok);
    try testing.expectEqualStrings("a=1; b=2; c=3", req.get("cookie").?);
    try testing.expectEqual(@as(usize, 1), countHeaders(req.headers, "cookie"));

    // Leading/trailing OWS or CTL in field value -> BadRequest
    try testing.expectError(error.BadRequest, buildRequest(arena, &[_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "x-bad", .value = " val" },
    }));
    try testing.expectError(error.BadRequest, buildRequest(arena, &[_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "x-bad", .value = "val\x7f" },
    }));

    // Invalid :method, :scheme, :path, userinfo@ in :authority, or empty :authority with host
    try testing.expectError(error.BadRequest, buildRequest(arena, &[_]hpack.Header{
        .{ .name = ":method", .value = "GET /" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    }));
    try testing.expectError(error.BadRequest, buildRequest(arena, &[_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "1https" },
        .{ .name = ":path", .value = "/" },
    }));
    try testing.expectError(error.BadRequest, buildRequest(arena, &[_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "relative-no-slash" },
    }));
    try testing.expectError(error.BadRequest, buildRequest(arena, &[_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "user@example.com" },
    }));
    try testing.expectError(error.BadRequest, buildRequest(arena, &[_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "" },
        .{ .name = "host", .value = "evil.example.com" },
    }));
}

test "server emits HPACK dynamic table size update (0) after peer SETTINGS_HEADER_TABLE_SIZE=0" {
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

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var srv_settings = try readFrameAlloc(testing.allocator, &reader.interface);
    srv_settings.deinit(testing.allocator);

    var st_zero: [6]u8 = undefined;
    putSetting(&st_zero, set_header_table_size, 0);
    try writeFrame(&writer.interface, .settings, 0, 0, &st_zero);
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");

    // Wait for server's SETTINGS(ACK) first.
    while (true) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        const is_ack = f.header.ftype == .settings and (f.header.flags & flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    // Send GET / request on stream 1.
    const req_block = [_]u8{ 0x82, 0x87, 0x84 }; // :method GET, :scheme https, :path /
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);

    var resp_hdr = try readFrameOfType(testing.allocator, &reader.interface, .headers);
    defer resp_hdr.deinit(testing.allocator);
    try testing.expect(resp_hdr.payload.len > 0);
    try testing.expectEqual(@as(u8, 0x20), resp_hdr.payload[0]); // RFC 7541 §6.3 size=0

    var dec = hpack.Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const decoded = try dec.decode(arena_state.allocator(), resp_hdr.payload);
    try testing.expectEqual(@as(usize, 0), dec.dyn.max_size);
    try testing.expectEqualStrings("200", findHeaderValue(decoded, ":status").?);
}

test "server GOAWAY last_stream_id stays non-increasing when streams are refused while draining" {
    const SlowHandler = struct {
        var entered = std.atomic.Value(bool).init(false);
        var release = std.atomic.Value(bool).init(false);
        fn handle(ctx: *types.Context) anyerror!void {
            entered.store(true, .release);
            while (!release.load(.acquire)) {
                Io.sleep(testing.io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
            }
            try ctx.res.send(200, "text/plain", "ok");
        }
    };
    SlowHandler.entered.store(false, .release);
    SlowHandler.release.store(false, .release);

    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = SlowHandler.handle,
        .config = .{},
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer {
        SlowHandler.release.store(true, .release);
        _ = c.close(fds[1]);
    }

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var s0 = try readFrameAlloc(testing.allocator, &reader.interface);
    s0.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");

    const req_block = [_]u8{ 0x82, 0x87, 0x84 };
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &req_block);
    while (!SlowHandler.entered.load(.acquire)) {
        Io.sleep(testing.io, .{ .nanoseconds = 5 * std.time.ns_per_ms }, .awake) catch {};
    }

    // Trigger graceful drain via peer GOAWAY(NO_ERROR), then open stream 3 (refused)
    // followed by a connection protocol error (PING on stream 1) to elicit server GOAWAY.
    var peer_ga: [8]u8 = @splat(0);
    std.mem.writeInt(u32, peer_ga[0..4], 0, .big);
    try writeFrame(&writer.interface, .goaway, 0, 0, &peer_ga);
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, &req_block);

    var rst = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 3), rst.header.sid);
    try testing.expectEqual(@as(u32, @backingInt(ErrorCode.refused_stream)), std.mem.readInt(u32, rst.payload[0..4], .big));

    // Stream 3 was refused (never processed), so a subsequent fatal GOAWAY must
    // still report last_stream_id == 1, NOT 3.
    const bad_ping: [8]u8 = @splat(0);
    try writeFrame(&writer.interface, .ping, 0, 1, &bad_ping);
    var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
    defer ga.deinit(testing.allocator);
    const last_id = std.mem.readInt(u32, ga.payload[0..4], .big) & 0x7fff_ffff;
    try testing.expectEqual(@as(u32, 1), last_id);
}

test "graceful drain times out a stream stalled waiting on missing peer DATA" {
    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = h2EchoHandler,
        .config = .{ .head_timeout_ms = 80, .idle_timeout_ms = 80 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer _ = c.close(fds[1]);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

    try writer.interface.writeAll(preface);
    try writer.interface.flush();
    var s0 = try readFrameAlloc(testing.allocator, &reader.interface);
    s0.deinit(testing.allocator);
    try writeFrame(&writer.interface, .settings, 0, 0, "");
    try writeFrame(&writer.interface, .settings, flag_ack, 0, "");

    // POST / without END_STREAM -> worker blocks in streamRead; then send graceful GOAWAY
    // and keep socket open without ever sending DATA.
    const post_block = [_]u8{ 0x83, 0x87, 0x84 }; // :method POST, :scheme https, :path /
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &post_block);
    var peer_ga: [8]u8 = @splat(0);
    try writeFrame(&writer.interface, .goaway, 0, 0, &peer_ga);

    const start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
    t.join(); // must exit promptly after the 80ms stall timeout without closing fds[1]!
    const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - start, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 2_000);
}

test "graceful drain bounds stalled stream even when peer sends continuous PINGs" {
    const RunState = struct {
        var done = std.atomic.Value(bool).init(false);
        fn serve(srv: *Server, fd: std.posix.fd_t) void {
            serveRawH2OnFd(srv, fd);
            done.store(true, .release);
        }
    };
    const configs = [_]Config{
        .{ .head_timeout_ms = 120, .idle_timeout_ms = 120 },
        .{ .head_timeout_ms = 30_000, .idle_timeout_ms = 180_000, .drain_timeout_ms = 120 },
    };
    for (configs) |cfg| {
        RunState.done.store(false, .release);
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);

        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = h2EchoHandler,
            .config = cfg,
        };
        const t = try std.Thread.spawn(.{}, RunState.serve, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);

        try writer.interface.writeAll(preface);
        try writer.interface.flush();
        var s0 = try readFrameAlloc(testing.allocator, &reader.interface);
        s0.deinit(testing.allocator);
        try writeFrame(&writer.interface, .settings, 0, 0, "");
        try writeFrame(&writer.interface, .settings, flag_ack, 0, "");

        const post_block = [_]u8{ 0x83, 0x87, 0x84 }; // POST / without END_STREAM
        try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &post_block);
        const peer_ga: [8]u8 = @splat(0);
        try writeFrame(&writer.interface, .goaway, 0, 0, &peer_ga);

        // Send PING every 25ms (< 120ms bound) while withholding DATA: server must
        // still enforce the anchored 120ms deadline and exit during the PING loop.
        const ping: [8]u8 = @splat(0x42);
        var exited_during_pings = false;
        var waited_ms: u64 = 0;
        while (waited_ms < 1_000) : (waited_ms += 25) {
            Io.sleep(testing.io, .{ .nanoseconds = 25 * std.time.ns_per_ms }, .awake) catch {};
            if (RunState.done.load(.acquire)) {
                exited_during_pings = true;
                break;
            }
            writeFrame(&writer.interface, .ping, 0, 0, &ping) catch {
                // EPIPE/closed peer socket means server exited right as we wrote.
                Io.sleep(testing.io, .{ .nanoseconds = 25 * std.time.ns_per_ms }, .awake) catch {};
                exited_during_pings = RunState.done.load(.acquire);
                break;
            };
        }
        try testing.expect(exited_during_pings);
    }
}

test "graceful drain bounds sendBody stall even when peer trickles conn WINDOW_UPDATEs" {
    const BigHandler = struct {
        fn handle(ctx: *types.Context) anyerror!void {
            const body = try ctx.arena.alloc(u8, 200 * 1024);
            @memset(body, 'a');
            try ctx.res.send(200, "application/octet-stream", body);
        }
    };
    const RunState = struct {
        var done = std.atomic.Value(bool).init(false);
        fn serve(srv: *Server, fd: std.posix.fd_t) void {
            serveRawH2OnFd(srv, fd);
            done.store(true, .release);
        }
    };
    const configs = [_]Config{
        .{ .head_timeout_ms = 120, .idle_timeout_ms = 120 },
        .{ .head_timeout_ms = 30_000, .idle_timeout_ms = 180_000, .drain_timeout_ms = 120 },
    };
    for (configs) |cfg| {
        RunState.done.store(false, .release);
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);

        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = BigHandler.handle,
            .config = cfg,
        };
        const t = try std.Thread.spawn(.{}, RunState.serve, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [8192]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);

        // Request a 200 KiB response and drain the initial 65535-byte window so
        // the stream's send_window hits 0 and the worker blocks in sendBody.
        try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
        var rx_data: usize = 0;
        while (rx_data < 65535) {
            var f = try readFrameAlloc(testing.allocator, &reader.interface);
            defer f.deinit(testing.allocator);
            if (f.header.ftype == .data and f.header.sid == 1) rx_data += f.payload.len;
        }

        const peer_ga: [8]u8 = @splat(0);
        try writeFrame(&writer.interface, .goaway, 0, 0, &peer_ga);

        // Trickle WINDOW_UPDATE(0, 1) on connection stream 0 every 25ms (< 120ms bound)
        // without crediting stream 1: send_cond wakes each time while avail stays 0,
        // which must NOT reset peer_wait_since_ns.
        var wu_one: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu_one, 1, .big);
        var exited_during_trickle = false;
        var waited_ms: u64 = 0;
        while (waited_ms < 1_000) : (waited_ms += 25) {
            Io.sleep(testing.io, .{ .nanoseconds = 25 * std.time.ns_per_ms }, .awake) catch {};
            if (RunState.done.load(.acquire)) {
                exited_during_trickle = true;
                break;
            }
            writeFrame(&writer.interface, .window_update, 0, 0, &wu_one) catch {
                Io.sleep(testing.io, .{ .nanoseconds = 25 * std.time.ns_per_ms }, .awake) catch {};
                exited_during_trickle = RunState.done.load(.acquire);
                break;
            };
        }
        try testing.expect(exited_during_trickle);
    }
}

test "ConnWriter poisons subsequent writes after a partial write failure" {
    const FailAfter5 = struct {
        written: usize = 0,
        writer: Io.Writer,
        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            _ = splat;
            const self: *@This() = @fieldParentPtr("writer", w);
            const chunk = data[0];
            if (self.written + chunk.len > 5) return error.WriteFailed;
            self.written += chunk.len;
            return chunk.len;
        }
    };
    var sink: FailAfter5 = .{
        .writer = .{
            .buffer = &.{},
            .vtable = &.{ .drain = FailAfter5.drain },
        },
    };
    var cw: ConnWriter = .{ .io = testing.io, .w = &sink.writer };
    const zero_ping: [8]u8 = @splat(0);
    try testing.expectError(error.WriteFailed, cw.frame(.ping, 0, 0, &zero_ping));
    try testing.expect(cw.broken);
    // A tiny subsequent write that would otherwise fit (< 5 bytes) must still fail immediately.
    try testing.expectError(error.WriteFailed, cw.frame(.settings, flag_ack, 0, ""));
}

test "buildRequest coalesces 1000 cookie headers in O(N) memory (#34)" {
    // 1000 cookies of 40 bytes each = ~42 KiB joined. The old O(N²) concat
    // loop allocated ~21 MiB on the request arena; with a 256 KiB fixed buffer
    // O(N²) immediately hits OutOfMemory while O(N) succeeds cleanly.
    const cookie_count: usize = 1000;
    const cookie_val = "session_part=0123456789abcdef01234567890"; // 40 bytes
    var decoded: [4 + cookie_count]hpack.Header = undefined;
    decoded[0] = .{ .name = ":method", .value = "GET" };
    decoded[1] = .{ .name = ":scheme", .value = "https" };
    decoded[2] = .{ .name = ":path", .value = "/cookies" };
    decoded[3] = .{ .name = ":authority", .value = "example.com" };
    for (0..cookie_count) |i| {
        decoded[4 + i] = .{ .name = "cookie", .value = cookie_val };
    }

    const backing = try testing.allocator.alloc(u8, 256 * 1024);
    defer testing.allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);
    const req = try buildRequest(fba.allocator(), &decoded);

    const joined = req.get("cookie").?;
    const expected_len = cookie_count * cookie_val.len + (cookie_count - 1) * 2;
    try testing.expectEqual(expected_len, joined.len);
    try testing.expect(std.mem.startsWith(u8, joined, cookie_val ++ "; " ++ cookie_val));
    try testing.expect(std.mem.endsWith(u8, joined, "; " ++ cookie_val));
    try testing.expectEqual(@as(usize, 1), countHeaders(req.headers, "cookie"));
}

test "RxRing bounds memory across sustained wrapped streaming reads (#35)" {
    var ring: RxRing = .{};
    defer ring.deinit(testing.allocator);

    // Seed 500 bytes so `ring.len` NEVER drops to 0 during the entire 512 KiB stream.
    var seed: [500]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i);
    try ring.appendSlice(testing.allocator, &seed);

    var write_seq: usize = seed.len;
    var read_seq: usize = 0;
    var wchunk: [700]u8 = undefined;
    var rchunk: [700]u8 = undefined;
    for (0..750) |_| {
        for (&wchunk) |*b| {
            b.* = @truncate(write_seq);
            write_seq += 1;
        }
        try ring.appendSlice(testing.allocator, &wchunk);
        const n = ring.read(&rchunk);
        try testing.expectEqual(rchunk.len, n);
        for (rchunk) |b| {
            try testing.expectEqual(@as(u8, @truncate(read_seq)), b);
            read_seq += 1;
        }
        try testing.expectEqual(@as(usize, 500), ring.len);
    }
    // Total streamed > 525 KiB with non-zero backlog throughout, yet backing
    // capacity stayed at the initial 4 KiB ring buffer!
    try testing.expect(ring.buf.len <= 8192);

    // Drain remaining 500 bytes and verify wrap-around growth preserves bytes.
    var tail: [500]u8 = undefined;
    try testing.expectEqual(@as(usize, 500), ring.read(&tail));
    for (tail) |b| {
        try testing.expectEqual(@as(u8, @truncate(read_seq)), b);
        read_seq += 1;
    }
    try testing.expectEqual(@as(usize, 0), ring.len);

    // Force growth while wrapped around the end of `ring.buf`.
    var pad: [3000]u8 = @splat('p');
    try ring.appendSlice(testing.allocator, &pad);
    var discard: [2500]u8 = undefined;
    try testing.expectEqual(@as(usize, 2500), ring.read(&discard)); // head=2500, len=500
    var wrap_part: [2000]u8 = @splat('w');
    try ring.appendSlice(testing.allocator, &wrap_part); // wraps past 4096
    var grow_part: [3000]u8 = @splat('g');
    try ring.appendSlice(testing.allocator, &grow_part); // triggers resize while wrapped
    try testing.expectEqual(@as(usize, 5500), ring.len);
    var out: [5500]u8 = undefined;
    try testing.expectEqual(@as(usize, 5500), ring.read(&out));
    try testing.expect(std.mem.allEqual(u8, out[0..500], 'p'));
    try testing.expect(std.mem.allEqual(u8, out[500..2500], 'w'));
    try testing.expect(std.mem.allEqual(u8, out[2500..5500], 'g'));
}

test "FloodGuard enforces sliding control-frame window and empty-DATA caps (#36)" {
    const cfg: Config = .{
        .max_control_frames_per_window = 5,
        .control_frame_window_ms = 1000,
        .max_empty_data_frames = 3,
    };
    var fg: FloodGuard = .{};
    const t0: i96 = 10 * std.time.ns_per_s;
    for (0..5) |_| try testing.expect(!fg.recordControl(t0, cfg));
    try testing.expect(fg.recordControl(t0, cfg)); // 6th in same window trips

    // After full windows elapse, slow periodic keepalive frames stay allowed.
    var fg2: FloodGuard = .{};
    var t: i96 = t0;
    for (0..20) |_| {
        try testing.expect(!fg2.recordControl(t, cfg));
        t += 2000 * std.time.ns_per_ms;
    }

    // Tail-of-window burst stays counted across a window boundary until a full
    // window elapses (PR #43 review #4).
    const big_cfg: Config = .{
        .max_control_frames_per_window = 500,
        .control_frame_window_ms = 10_000,
    };
    var fg_tail: FloodGuard = .{};
    const t_base: i96 = 100 * std.time.ns_per_s;
    try testing.expect(!fg_tail.recordControl(t_base, big_cfg)); // initializes at t=0s
    // 499 frames at t = 9.5s (total 500 within [0s, 10s]).
    for (0..499) |_| try testing.expect(!fg_tail.recordControl(t_base + 9_500 * std.time.ns_per_ms, big_cfg));
    // At t = 19.0s (9.5s after the 499 burst), those 499 are still inside the
    // 10s sliding window, so 2 more frames (total 501) must trip immediately.
    try testing.expect(!fg_tail.recordControl(t_base + 19_000 * std.time.ns_per_ms, big_cfg));
    try testing.expect(fg_tail.recordControl(t_base + 19_000 * std.time.ns_per_ms, big_cfg));
    // Once a full window past t = 9.5s elapses (t = 20.6s), the 499 burst has expired.
    try testing.expect(!fg_tail.recordControl(t_base + 20_600 * std.time.ns_per_ms, big_cfg));

    // Consecutive empty DATA caps at 3 and resets on non-empty DATA.
    var fg3: FloodGuard = .{};
    try testing.expect(!fg3.recordEmptyData(t0, cfg));
    try testing.expect(!fg3.recordEmptyData(t0, cfg));
    fg3.resetEmptyData();
    try testing.expect(!fg3.recordEmptyData(t0, cfg));
    try testing.expect(!fg3.recordEmptyData(t0, cfg));
    try testing.expect(!fg3.recordEmptyData(t0, cfg));
    try testing.expect(fg3.recordEmptyData(t0, cfg)); // 4th consecutive empty DATA trips
}

test "server GOAWAYs ENHANCE_YOUR_CALM on PING, SETTINGS, PRIORITY, and empty DATA floods (#36)" {
    const Case = enum { ping, settings, priority, empty_data, padded_empty_data };
    for ([_]Case{ .ping, .settings, .priority, .empty_data, .padded_empty_data }) |tc| {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);

        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = h2EchoHandler,
            .config = .{
                .max_control_frames_per_window = 8,
                .control_frame_window_ms = 10_000,
                .max_empty_data_frames = 4,
            },
        };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);

        switch (tc) {
            .ping => {
                const ping: [8]u8 = @splat(0x11);
                for (0..12) |_| writeFrame(&writer.interface, .ping, 0, 0, &ping) catch break;
            },
            .settings => {
                for (0..12) |_| writeFrame(&writer.interface, .settings, 0, 0, "") catch break;
            },
            .priority => {
                const prio: [5]u8 = .{ 0, 0, 0, 0, 16 };
                for (0..12) |_| writeFrame(&writer.interface, .priority, 0, 1, &prio) catch break;
            },
            .empty_data => {
                const post = [_]u8{ 0x83, 0x87, 0x84 };
                try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &post);
                for (0..8) |_| writeFrame(&writer.interface, .data, 0, 1, "") catch break;
            },
            .padded_empty_data => {
                const post = [_]u8{ 0x83, 0x87, 0x84 };
                try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &post);
                const pad_only = [_]u8{ 3, 0, 0, 0 }; // 0 unpadded body bytes
                for (0..8) |_| writeFrame(&writer.interface, .data, flag_padded, 1, &pad_only) catch break;
            },
        }

        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        const code = std.mem.readInt(u32, ga.payload[4..8], .big);
        try testing.expectEqual(@backingInt(ErrorCode.enhance_your_calm), code);
    }
}

test "server rejects te header in request trailers and non-tchar header names (#37)" {
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

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Stream 1: valid POST headers + trailing HEADERS containing `te: trailers` -> RST(PROTOCOL_ERROR).
    const post = [_]u8{ 0x83, 0x87, 0x84 };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &post);
    var t_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer t_arena.deinit();
    var t_block: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeTrailers(t_arena.allocator(), &t_block, &.{.{ .name = "te", .value = "trailers" }});
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, t_block.items);

    var rst1 = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst1.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 1), rst1.header.sid);
    try testing.expectEqual(@backingInt(ErrorCode.protocol_error), std.mem.readInt(u32, rst1.payload[0..4], .big));

    // Stream 3: header name containing delimiter `=` -> RST(PROTOCOL_ERROR).
    var bad_block: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeRequest(t_arena.allocator(), &bad_block, "GET", "https", "/", "example.com", &.{
        .{ .name = "bad=name", .value = "1" },
    });
    try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 3, bad_block.items);

    var rst3 = try readFrameOfType(testing.allocator, &reader.interface, .rst_stream);
    defer rst3.deinit(testing.allocator);
    try testing.expectEqual(@as(u31, 3), rst3.header.sid);
    try testing.expectEqual(@backingInt(ErrorCode.protocol_error), std.mem.readInt(u32, rst3.payload[0..4], .big));
}

test "server SETTINGS clamps initial_window_size, advertises MAX_HEADER_LIST_SIZE, and catches in-order overflow (#38)" {
    // Part A: clamping initial_window_size > 2^31-1 and advertising MAX_HEADER_LIST_SIZE.
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = h2TestHandler,
            .config = .{ .initial_window_size = 0xffff_ffff },
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

        var init_win: ?u32 = null;
        var max_hdr_list: ?u32 = null;
        var i: usize = 0;
        while (i + 6 <= s.payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, s.payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, s.payload[i + 2 ..][0..4], .big);
            if (id == set_initial_window_size) init_win = val;
            if (id == set_max_header_list_size) max_hdr_list = val;
        }
        try testing.expectEqual(@as(?u32, 0x7fff_ffff), init_win);
        try testing.expectEqual(@as(?u32, @intCast(hpack.default_max_header_list_size)), max_hdr_list);
    }

    // Part B: repeated INITIAL_WINDOW_SIZE in one SETTINGS frame catches intermediate overflow.
    {
        const HoldHandler = struct {
            var entered = std.atomic.Value(bool).init(false);
            var release = std.atomic.Value(bool).init(false);
            fn handle(ctx: *types.Context) anyerror!void {
                entered.store(true, .release);
                while (!release.load(.acquire)) {
                    Io.sleep(testing.io, .{ .nanoseconds = 5 * std.time.ns_per_ms }, .awake) catch {};
                }
                try ctx.res.send(200, "text/plain", "ok");
            }
        };
        HoldHandler.entered.store(false, .release);
        HoldHandler.release.store(false, .release);

        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = HoldHandler.handle,
            .config = .{},
        };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer t.join();
        defer {
            HoldHandler.release.store(true, .release);
            _ = c.close(fds[1]);
        }

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);

        try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
        while (!HoldHandler.entered.load(.acquire)) {
            Io.sleep(testing.io, .{ .nanoseconds = 5 * std.time.ns_per_ms }, .awake) catch {};
        }

        // Push stream 1's send_window to 2^31-1, then send a single SETTINGS frame
        // raising initial_window_size to 65536 (overflow!) followed immediately by
        // lowering it back to 65535.
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, 0x7fff_ffff - 65535, .big);
        try writeFrame(&writer.interface, .window_update, 0, 1, &wu);

        var s2: [12]u8 = undefined;
        putSetting(s2[0..6], set_initial_window_size, 65536);
        putSetting(s2[6..12], set_initial_window_size, 65535);
        try writeFrame(&writer.interface, .settings, 0, 0, &s2);

        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@backingInt(ErrorCode.flow_control_error), std.mem.readInt(u32, ga.payload[4..8], .big));
    }

    // Part C: applyInitialWindow releases streams_mu and send_mu BEFORE writing GOAWAY.
    {
        const LockCheckWriter = struct {
            conn: *Connection = undefined,
            saw_write: bool = false,
            streams_unlocked: bool = false,
            send_unlocked: bool = false,
            writer: Io.Writer,

            fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
                _ = splat;
                const self: *@This() = @fieldParentPtr("writer", w);
                if (!self.saw_write) {
                    self.saw_write = true;
                    if (self.conn.streams_mu.tryLock()) {
                        self.streams_unlocked = true;
                        self.conn.streams_mu.unlock(testing.io);
                    }
                    if (self.conn.send_mu.tryLock()) {
                        self.send_unlocked = true;
                        self.conn.send_mu.unlock(testing.io);
                    }
                }
                return data[0].len;
            }
        };
        var lcw: LockCheckWriter = .{
            .writer = .{ .buffer = &.{}, .vtable = &.{ .drain = LockCheckWriter.drain } },
        };
        var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = h2TestHandler };
        var conn: Connection = .{
            .srv = &srv,
            .gpa = testing.allocator,
            .io = testing.io,
            .cw = .{ .io = testing.io, .w = &lcw.writer },
            .decoder = hpack.Decoder.init(testing.allocator, our_header_table_size),
        };
        defer conn.deinit();
        lcw.conn = &conn;

        const st = try testing.allocator.create(H2Stream);
        defer testing.allocator.destroy(st);
        st.* = .{
            .conn = &conn,
            .id = 1,
            .arena_state = std.heap.ArenaAllocator.init(testing.allocator),
            .req = undefined,
            .send_window = 0x7fff_ffff,
        };
        defer st.arena_state.deinit();
        try conn.streams.put(testing.allocator, 1, st);
        defer _ = conn.streams.remove(1);

        try testing.expect(!applyInitialWindow(&conn, 65536));
        try testing.expect(lcw.saw_write);
        try testing.expect(lcw.streams_unlocked);
        try testing.expect(lcw.send_unlocked);
    }
}

test "H2Sink coalesces Response.send and empty/204 responses into a single flush (#41)" {
    const CountingWriter = struct {
        flushes: usize = 0,
        bytes: std.ArrayList(u8) = .empty,
        writer: Io.Writer,

        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", w);
            // Count each flush/drain that emits buffered output.
            var total: usize = 0;
            if (w.end > 0) {
                self.bytes.appendSlice(testing.allocator, w.buffer[0..w.end]) catch return error.WriteFailed;
                w.end = 0;
            }
            if (data.len > 0) {
                for (data[0 .. data.len - 1]) |s| {
                    self.bytes.appendSlice(testing.allocator, s) catch return error.WriteFailed;
                    total += s.len;
                }
                const last = data[data.len - 1];
                for (0..splat) |_| {
                    self.bytes.appendSlice(testing.allocator, last) catch return error.WriteFailed;
                    total += last.len;
                }
            }
            self.flushes += 1;
            return total;
        }
    };

    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = h2TestHandler };

    // Case 1: Response.send with non-empty body -> HEADERS + DATA(END_STREAM) in 1 flush.
    {
        var buf: [4096]u8 = undefined;
        var cw_sink: CountingWriter = .{
            .writer = .{ .buffer = &buf, .vtable = &.{ .drain = CountingWriter.drain } },
        };
        defer cw_sink.bytes.deinit(testing.allocator);

        var conn: Connection = .{
            .srv = &srv,
            .gpa = testing.allocator,
            .io = testing.io,
            .cw = .{ .io = testing.io, .w = &cw_sink.writer },
            .decoder = hpack.Decoder.init(testing.allocator, our_header_table_size),
        };
        defer conn.deinit();

        var st: H2Stream = .{
            .conn = &conn,
            .id = 1,
            .arena_state = std.heap.ArenaAllocator.init(testing.allocator),
            .req = undefined,
            .send_window = default_window,
        };
        defer st.arena_state.deinit();

        var h2: H2Sink = .{ .stream = &st };
        var res: types.Response = .{ .arena = st.arena(), .sink = h2.sink(), .minor_version = 0 };
        try res.send(200, "text/plain", "coalesced");
        try res.finish(); // idempotent no-op

        try testing.expectEqual(@as(usize, 1), cw_sink.flushes);
        try testing.expectEqual(@as(u64, 9), res.body_bytes);

        // Parse the two frames: HEADERS(END_HEADERS) + DATA(END_STREAM).
        const wire = cw_sink.bytes.items;
        const fh1 = parseHeader(wire[0..9]);
        try testing.expectEqual(FrameType.headers, fh1.ftype);
        try testing.expectEqual(@as(u8, 0), fh1.flags & flag_end_stream);
        const off2 = 9 + fh1.length;
        const fh2 = parseHeader(wire[off2..][0..9]);
        try testing.expectEqual(FrameType.data, fh2.ftype);
        try testing.expectEqual(flag_end_stream, fh2.flags & flag_end_stream);
        try testing.expectEqualStrings("coalesced", wire[off2 + 9 ..][0..fh2.length]);
        try testing.expectEqual(off2 + 9 + fh2.length, wire.len);
    }

    // Case 2: 204 No Content (finish without write) -> single HEADERS(END_STREAM) in 1 flush.
    {
        var buf: [4096]u8 = undefined;
        var cw_sink: CountingWriter = .{
            .writer = .{ .buffer = &buf, .vtable = &.{ .drain = CountingWriter.drain } },
        };
        defer cw_sink.bytes.deinit(testing.allocator);

        var conn: Connection = .{
            .srv = &srv,
            .gpa = testing.allocator,
            .io = testing.io,
            .cw = .{ .io = testing.io, .w = &cw_sink.writer },
            .decoder = hpack.Decoder.init(testing.allocator, our_header_table_size),
        };
        defer conn.deinit();

        var st: H2Stream = .{
            .conn = &conn,
            .id = 3,
            .arena_state = std.heap.ArenaAllocator.init(testing.allocator),
            .req = undefined,
            .send_window = default_window,
        };
        defer st.arena_state.deinit();

        var h2: H2Sink = .{ .stream = &st };
        var res: types.Response = .{ .arena = st.arena(), .sink = h2.sink(), .minor_version = 0 };
        res.status(204);
        try res.finish();

        try testing.expectEqual(@as(usize, 1), cw_sink.flushes);
        const wire = cw_sink.bytes.items;
        const fh = parseHeader(wire[0..9]);
        try testing.expectEqual(FrameType.headers, fh.ftype);
        try testing.expectEqual(flag_end_headers | flag_end_stream, fh.flags);
        try testing.expectEqual(9 + fh.length, wire.len);
    }
}

test "Server.requestStop wakes idle connections immediately with GOAWAY(NO_ERROR) (#42)" {
    // Part A: completely idle connection with 60s idle_timeout_ms exits immediately.
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = h2TestHandler,
            .config = .{ .idle_timeout_ms = 60_000 },
        };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        // Give the server reader time to enter readIdleHeader on idle_timeout_ms=60s.
        Io.sleep(testing.io, .{ .nanoseconds = 40 * std.time.ns_per_ms }, .awake) catch {};

        const start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
        srv.requestStop();

        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@backingInt(ErrorCode.no_error), std.mem.readInt(u32, ga.payload[4..8], .big));
        t.join(); // exits cleanly without closing fds[1] first!
        const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - start, std.time.ns_per_ms);
        try testing.expect(elapsed_ms < 1_000);
    }

    // Part B: connection with an in-flight slow handler emits GOAWAY immediately
    // on requestStop(), allows the handler to finish, and drains gracefully.
    {
        const SlowHandler = struct {
            var entered = std.atomic.Value(bool).init(false);
            fn handle(ctx: *types.Context) anyerror!void {
                entered.store(true, .release);
                Io.sleep(ctx.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};
                try ctx.res.send(200, "text/plain", "drained-ok");
            }
        };
        SlowHandler.entered.store(false, .release);

        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = SlowHandler.handle,
            .config = .{ .idle_timeout_ms = 60_000 },
        };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);

        try writeFrame(&writer.interface, .headers, flag_end_headers | flag_end_stream, 1, &trailers_req_block);
        while (!SlowHandler.entered.load(.acquire)) {
            Io.sleep(testing.io, .{ .nanoseconds = 5 * std.time.ns_per_ms }, .awake) catch {};
        }
        Io.sleep(testing.io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};

        const start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
        srv.requestStop();

        var saw_goaway = false;
        var saw_body = false;
        while (!(saw_goaway and saw_body)) {
            var f = try readFrameAlloc(testing.allocator, &reader.interface);
            defer f.deinit(testing.allocator);
            if (f.header.ftype == .goaway) {
                try testing.expectEqual(@backingInt(ErrorCode.no_error), std.mem.readInt(u32, f.payload[4..8], .big));
                saw_goaway = true;
            } else if (f.header.ftype == .data and f.header.sid == 1) {
                try testing.expectEqualStrings("drained-ok", f.payload);
                saw_body = true;
            }
        }
        t.join();
        const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - start, std.time.ns_per_ms);
        try testing.expect(elapsed_ms < 1_000);
    }

    // Part C: a single `requestStop()` broadcasts to ALL idle connections (manual-reset Io.Event).
    {
        const conn_count = 3;
        var fds_arr: [conn_count][2]c_int = undefined;
        var threads: [conn_count]std.Thread = undefined;
        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = h2TestHandler,
            .config = .{ .idle_timeout_ms = 60_000 },
        };
        for (0..conn_count) |i| {
            fds_arr[i] = try newSocketPair();
            threads[i] = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds_arr[i][0] });
        }
        defer {
            for (0..conn_count) |i| _ = c.close(fds_arr[i][1]);
        }

        var rbufs: [conn_count][4096]u8 = undefined;
        var wbufs: [conn_count][4096]u8 = undefined;
        for (0..conn_count) |i| {
            var r = peerStream(fds_arr[i][1]).reader(testing.io, &rbufs[i]);
            var w = peerStream(fds_arr[i][1]).writer(testing.io, &wbufs[i]);
            try rawHandshake(&r.interface, &w.interface);
        }
        Io.sleep(testing.io, .{ .nanoseconds = 40 * std.time.ns_per_ms }, .awake) catch {};

        const start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
        srv.requestStop();

        for (0..conn_count) |i| {
            var r = peerStream(fds_arr[i][1]).reader(testing.io, &rbufs[i]);
            var ga = try readFrameOfType(testing.allocator, &r.interface, .goaway);
            defer ga.deinit(testing.allocator);
            try testing.expectEqual(@backingInt(ErrorCode.no_error), std.mem.readInt(u32, ga.payload[4..8], .big));
            threads[i].join();
        }
        const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - start, std.time.ns_per_ms);
        try testing.expect(elapsed_ms < 1_000);
    }

    // Part D: async-signal-safe bare `srv.stop.store(true, .release)` (without
    // calling `requestStop()` and with a completely silent peer) still wakes an
    // idle connection promptly instead of sleeping for `idle_timeout_ms`.
    {
        const fds = try newSocketPair();
        errdefer _ = c.close(fds[1]);
        var srv: Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .handler = h2TestHandler,
            .config = .{ .idle_timeout_ms = 60_000 },
        };
        const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
        defer _ = c.close(fds[1]);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
        var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
        try rawHandshake(&reader.interface, &writer.interface);
        Io.sleep(testing.io, .{ .nanoseconds = 40 * std.time.ns_per_ms }, .awake) catch {};

        const start = Io.Timestamp.now(testing.io, .awake).nanoseconds;
        srv.stop.store(true, .release);

        var ga = try readFrameOfType(testing.allocator, &reader.interface, .goaway);
        defer ga.deinit(testing.allocator);
        try testing.expectEqual(@backingInt(ErrorCode.no_error), std.mem.readInt(u32, ga.payload[4..8], .big));
        t.join();
        const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - start, std.time.ns_per_ms);
        try testing.expect(elapsed_ms < 1_000);
    }
}

test "H2Sink.sendComplete restores both stream and connection send windows on pre-wire StreamReset" {
    const NoopWriter = struct {
        writer: Io.Writer,
        fn drain(_: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
            return data[0].len;
        }
    };
    var nw: NoopWriter = .{ .writer = .{ .buffer = &.{}, .vtable = &.{ .drain = NoopWriter.drain } } };
    var srv: Server = .{ .io = testing.io, .gpa = testing.allocator, .handler = h2TestHandler };
    var conn: Connection = .{
        .srv = &srv,
        .gpa = testing.allocator,
        .io = testing.io,
        .cw = .{ .io = testing.io, .w = &nw.writer },
        .decoder = hpack.Decoder.init(testing.allocator, our_header_table_size),
    };
    defer conn.deinit();

    var st: H2Stream = .{
        .conn = &conn,
        .id = 1,
        .arena_state = std.heap.ArenaAllocator.init(testing.allocator),
        .req = undefined,
        .send_window = default_window,
    };
    defer st.arena_state.deinit();

    // Hold cw.mu? No — simulate reset flipping right before writeHeadersWithData by
    // poisoning cw.lock? Instead test the pre-wire reset path directly via cw.lock race:
    // mark st.reset inside a concurrent thread isn't needed if we invoke writeHeadersWithData
    // check after deducting. Simplest deterministic check: call sendBodyImpl when reset flips
    // between send_mu and cw.mu via a wrapper, OR verify both windows equal default_window
    // when cw.frameForStream sees reset. We can hold cw.mu on another thread, set st.reset,
    // and release cw.mu so sendComplete enters writeHeadersWithData AFTER reserving first_n!
    const HoldCtx = struct {
        conn: *Connection,
        st: *H2Stream,
        locked: std.atomic.Value(bool) = .init(false),
        fn run(ctx: *@This()) void {
            ctx.conn.cw.lock();
            ctx.locked.store(true, .release);
            Io.sleep(testing.io, .{ .nanoseconds = 40 * std.time.ns_per_ms }, .awake) catch {};
            ctx.st.reset.store(true, .release);
            ctx.conn.cw.unlock();
        }
    };
    var hctx: HoldCtx = .{ .conn = &conn, .st = &st };
    const th = try std.Thread.spawn(.{}, HoldCtx.run, .{&hctx});
    defer th.join();
    while (!hctx.locked.load(.acquire)) {
        Io.sleep(testing.io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
    }

    var h2: H2Sink = .{ .stream = &st };
    var res: types.Response = .{ .arena = st.arena(), .sink = h2.sink(), .minor_version = 0 };
    try testing.expectError(error.StreamReset, res.send(200, "text/plain", "hello world"));
    try testing.expectEqual(default_window, st.send_window);
    try testing.expectEqual(default_window, conn.send_window);
}

test "server flushes sub-threshold connection recv credit when a stream completes" {
    const DrainHandler = struct {
        fn handle(ctx: *types.Context) anyerror!void {
            if (ctx.body_reader) |br| {
                var tmp: [4096]u8 = undefined;
                while (true) {
                    const n = try br.read(&tmp);
                    if (n == 0) break;
                }
            }
            try ctx.res.send(200, "text/plain", "drained");
        }
    };

    const fds = try newSocketPair();
    errdefer _ = c.close(fds[1]);
    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = DrainHandler.handle,
        .config = .{ .connection_window_size = 1 << 20, .idle_timeout_ms = 5_000 },
    };
    const t = try std.Thread.spawn(.{}, serveRawH2OnFd, .{ &srv, fds[0] });
    defer t.join();
    defer _ = c.close(fds[1]);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [32768]u8 = undefined;
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);
    var writer = peerStream(fds[1]).writer(testing.io, &wbuf);
    try rawHandshake(&reader.interface, &writer.interface);

    // Drain the initial handshake stream-0 WINDOW_UPDATE before starting stream 1.
    const ping: [8]u8 = @splat(0xaa);
    try writeFrame(&writer.interface, .ping, 0, 0, &ping);
    while (true) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        const is_pong = f.header.ftype == .ping and (f.header.flags & flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_pong) break;
    }

    // Upload 20 KiB (far below 512 KiB half-window threshold). When the handler
    // finishes stream 1, the server must flush stream-0 WINDOW_UPDATE(20480).
    const post = [_]u8{ 0x83, 0x87, 0x84 };
    try writeFrame(&writer.interface, .headers, flag_end_headers, 1, &post);
    var payload: [10240]u8 = @splat('u');
    try writeFrame(&writer.interface, .data, 0, 1, &payload);
    try writeFrame(&writer.interface, .data, flag_end_stream, 1, &payload);

    var conn_wu: u32 = 0;
    var saw_end = false;
    while (!saw_end or conn_wu < 20480) {
        var f = try readFrameAlloc(testing.allocator, &reader.interface);
        defer f.deinit(testing.allocator);
        if (f.header.ftype == .window_update and f.header.sid == 0) {
            conn_wu += std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
        } else if (f.header.sid == 1 and (f.header.ftype == .data or f.header.ftype == .headers) and (f.header.flags & flag_end_stream != 0)) {
            saw_end = true;
        }
    }
    try testing.expectEqual(@as(u32, 20480), conn_wu);
}

test "runTimed handles huge millisecond timeout without u64 multiplication overflow" {
    const Noop = struct {
        fn work() anyerror!void {}
    };
    // Exceeds maxInt(u64) / ns_per_ms (~1.84e13); previously panicked in timerThunk.
    try runTimed(testing.io, std.math.maxInt(u64) / 2, Noop.work, .{});
}

test "server discards DATA, trailers, and WINDOW_UPDATE on an already-reset stream still unwinding" {
    const NoopHandler = struct {
        fn handle(_: *types.Context) anyerror!void {}
    };
    const fds = try newSocketPair();
    defer _ = c.close(fds[0]);
    defer _ = c.close(fds[1]);

    var wbuf: [4096]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var writer = peerStream(fds[0]).writer(testing.io, &wbuf);
    var reader = peerStream(fds[1]).reader(testing.io, &rbuf);

    var srv: Server = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .handler = NoopHandler.handle,
        .config = .{ .max_empty_data_frames = 2 },
    };
    var conn: Connection = .{
        .srv = &srv,
        .gpa = testing.allocator,
        .io = testing.io,
        .cw = .{ .io = testing.io, .w = &writer.interface },
        .decoder = hpack.Decoder.init(testing.allocator, our_header_table_size),
        .highest_stream_id = 1,
        .conn_recv_window = 1 << 20,
    };
    defer conn.deinit();

    const st = try testing.allocator.create(H2Stream);
    defer {
        st.rx_buf.deinit(testing.allocator);
        st.arena_state.deinit();
        testing.allocator.destroy(st);
    }
    st.* = .{
        .conn = &conn,
        .id = 1,
        .arena_state = std.heap.ArenaAllocator.init(testing.allocator),
        .req = .{
            .method = "POST",
            .target = "/",
            .minor_version = 0,
            .headers = &.{},
            .content_length = null,
            .keep_alive = true,
        },
        .send_window = 0x7fff_ffff,
        .recv_window = 65535,
        .reset = .init(true),
    };
    try conn.streams.put(testing.allocator, 1, st);

    // 1. DATA on the already-reset stream must NOT buffer into rx_buf or shrink
    //    st.recv_window, and MUST immediately return connection window credit.
    var body: [1024]u8 = @splat('x');
    try testing.expect(handleData(&conn, .{ .length = body.len, .ftype = .data, .flags = 0, .sid = 1 }, &body));
    try testing.expectEqual(@as(usize, 0), st.rx_buf.len);
    try testing.expectEqual(@as(i64, 65535), st.recv_window);
    try testing.expectEqual(@as(i64, 1 << 20), conn.conn_recv_window);
    var wu = try readFrameAlloc(testing.allocator, &reader.interface);
    defer wu.deinit(testing.allocator);
    try testing.expectEqual(FrameType.window_update, wu.header.ftype);
    try testing.expectEqual(@as(u31, 0), wu.header.sid);
    try testing.expectEqual(@as(u32, 1024), std.mem.readInt(u32, wu.payload[0..4], .big) & 0x7fff_ffff);

    // 2. Trailing HEADERS on the already-reset stream must advance HPACK without
    //    setting rx_eof or emitting another RST_STREAM.
    var trailer_block: std.ArrayList(u8) = .empty;
    defer trailer_block.deinit(testing.allocator);
    try hpack.Encoder.encodeTrailers(testing.allocator, &trailer_block, &.{.{ .name = "x-tr", .value = "1" }});
    try handleTrailingHeaders(&conn, .{ .length = @intCast(trailer_block.items.len), .ftype = .headers, .flags = flag_end_headers | flag_end_stream, .sid = 1 }, trailer_block.items);
    try testing.expect(!st.rx_eof);

    // 3. WINDOW_UPDATE and SETTINGS_INITIAL_WINDOW_SIZE ignore the already-reset
    //    stream (no false overflow on its max send_window).
    var wu_payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu_payload, 100, .big);
    try testing.expect(handleWindowUpdate(&conn, .{ .length = 4, .ftype = .window_update, .flags = 0, .sid = 1 }, &wu_payload));
    try testing.expectEqual(@as(i64, 0x7fff_ffff), st.send_window);
    try testing.expect(applyInitialWindow(&conn, 65536));
    try testing.expectEqual(@as(i64, 0x7fff_ffff), st.send_window);

    // 4. Empty DATA flood on an already-reset stream still trips ENHANCE_YOUR_CALM.
    try testing.expect(handleData(&conn, .{ .length = 0, .ftype = .data, .flags = 0, .sid = 1 }, ""));
    try testing.expect(handleData(&conn, .{ .length = 0, .ftype = .data, .flags = 0, .sid = 1 }, ""));
    try testing.expect(!handleData(&conn, .{ .length = 0, .ftype = .data, .flags = 0, .sid = 1 }, ""));
    var ga = try readFrameAlloc(testing.allocator, &reader.interface);
    defer ga.deinit(testing.allocator);
    try testing.expectEqual(FrameType.goaway, ga.header.ftype);
    try testing.expectEqual(@backingInt(ErrorCode.enhance_your_calm), std.mem.readInt(u32, ga.payload[4..8], .big));
}
