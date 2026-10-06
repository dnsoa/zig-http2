//! HTTP/2 client on the shared wire primitives (`proto.zig`) and HPACK codec.
//!
//! Multiplexed: many concurrent streams on one connection. A background reader
//! thread demultiplexes inbound frames into per-stream queues and handles
//! SETTINGS/PING/WINDOW_UPDATE housekeeping. Send-side DATA is flow-controlled
//! against the peer's connection + per-stream windows. Transport-agnostic — the
//! caller passes an `Io.Reader`/`Io.Writer` (TLS-wrapped for real connections).
//!
//! Usage:
//!   ```zig
//!   var c: h2.Client = undefined;
//!   try c.init(io, gpa, &reader, &writer);
//!   defer c.deinit();
//!   const s = try c.openStream(.{ .path = "/svc/Echo" }, false);
//!   try s.send("ping", true);
//!   switch (try s.readEvent(arena)) { .headers => ..., .data => ..., ... }
//!   ```
//! `deinit` stops the reader; close the transport around it so the reader's
//! blocking read returns. Keepalive (optional) detects half-open peers.

const std = @import("std");
const Io = std.Io;
const hpack = @import("hpack.zig");
const p2 = @import("proto.zig");

pub const Header = hpack.Header;

pub const RequestHead = struct {
    method: []const u8 = "POST",
    scheme: []const u8 = "https",
    path: []const u8,
    authority: []const u8 = "",
    headers: []const Header = &.{},
};

/// A surfaced stream event. Housekeeping frames (SETTINGS/PING/WINDOW_UPDATE)
/// are handled internally and never surfaced.
pub const Event = union(enum) {
    /// Response HEADERS (initial) or trailing HEADERS. `end_stream` marks the
    /// end of the stream (trailers, or a Trailers-Only response).
    headers: struct { sid: u31, headers: []const Header, end_stream: bool },
    data: struct { sid: u31, payload: []const u8, end_stream: bool },
    rst: struct { sid: u31, code: u32 },
    goaway,
};

/// One inbound item buffered on a stream's queue (gpa-owned until delivered).
/// DATA carries its flow-control cost (the whole frame: pad octet + data +
/// padding) so the window is credited only when the caller consumes it.
const Queued = union(enum) {
    headers: []const Header,
    data: struct { bytes: []u8, fc_cost: u32 },
};

/// How often the reader's blocking read wakes when no keepalive is configured,
/// so `deinit` (which sets `dead`) stops the reader within this window.
const reader_wake_ms: u64 = 50;

/// Max inbound frame size we accept, advertised as SETTINGS_MAX_FRAME_SIZE.
/// Equals the RFC default/minimum; we never advertise larger, so a larger frame
/// is a peer error we reject rather than allocate for.
const max_recv_frame: u32 = p2.our_max_frame_size; // 16384
/// Hard cap on one response's accumulated header block across HEADERS +
/// CONTINUATION (CVE-2024-27316 class); matches the server's bound.
const max_header_block: usize = 256 * 1024;
/// Cap on CONTINUATION frames per header block, mirroring the server's. Bytes
/// are already bounded by `max_header_block`, but a zero-length CONTINUATION
/// adds none, so a peer streaming empty ones makes no byte progress and the
/// size cap never fires — `readContinuations` would loop forever. A legitimate
/// block needs a handful (256KiB / 16KiB ⇒ ~16), so this is generous.
const max_continuation_frames: usize = 256;

/// Tunables for a client connection. `init` uses the defaults; pass your own
/// through `initWithConfig`.
pub const Config = struct {
    /// Connection-level inbound flow-control window, aggregated across streams.
    /// The RFC's fixed initial value is 65535 and a connection window can only
    /// be enlarged via WINDOW_UPDATE, so anything larger is advertised with a
    /// stream-0 WINDOW_UPDATE right after the preface. Clamped to
    /// [65535, 2^31-1].
    ///
    /// This is a throughput knob, and 65535 is a low ceiling: a client pulling
    /// a large response can have at most one window in flight per round trip,
    /// so it tops out near `window / RTT` regardless of bandwidth (~1.3 MB/s at
    /// 50 ms). Loopback hides it entirely. Mirrors the server's
    /// `Config.connection_window_size`, and shares its default.
    connection_window_size: u32 = 1 << 20,
    /// SETTINGS_INITIAL_WINDOW_SIZE we advertise: the peer's initial send
    /// window into each stream we open. Clamped to [0, 2^31-1].
    ///
    /// Raising it above the RFC default is safe in a way lowering it is not —
    /// a peer that has yet to process our SETTINGS uses 65535, which is more
    /// conservative than what we are asking for, never less.
    initial_window_size: u32 = 1 << 20,
};

pub const Stream = struct {
    client: *Client,
    id: u31,
    /// Flow-control window for DATA we send, guarded by `client.send_mu`.
    send_window: i64,
    /// Flow-control window for DATA we receive (RFC 7540 §6.9.2), decremented
    /// by the reader thread on each DATA frame and credited back as the caller
    /// consumes items. Guarded by `recv_mu`; written by the reader under
    /// streams_mu -> recv_mu, read/credited by readEvent under recv_mu.
    recv_window: i64 = p2.default_window,

    recv_mu: Io.Mutex = .init,
    recv_cond: Io.Condition = .init,
    queue: std.ArrayList(Queued) = .empty,
    /// end_stream flags for the queued items — tracked alongside so a queued
    /// DATA/HEADERS can report whether it closes the stream.
    end_flags: std.ArrayList(bool) = .empty,
    is_headers: std.ArrayList(bool) = .empty,
    /// Read cursor into the queues: `readEvent` advances this instead of
    /// `orderedRemove(0)` (which is O(n) per event → O(n²) per stream). The
    /// backing arrays are cleared once fully drained (`q_head == len`), which
    /// happens every flow-control cycle, so they stay bounded.
    q_head: usize = 0,
    reset: ?u32 = null,
    rst_delivered: bool = false,
    remote_closed: bool = false,
    /// Set by a local `cancel()` so a blocked `readEvent` wakes and returns
    /// `error.StreamCancelled` instead of hanging until the peer acts (RST to
    /// the peer does not, by itself, unblock our own reader). Guarded by
    /// `recv_mu`; distinct from `reset`, which is a peer-initiated RST_STREAM.
    cancelled: bool = false,
    /// Set when the stream is reset (peer RST_STREAM). Read by `send` without
    /// holding `recv_mu`, so it is atomic; lets a send blocked on the flow
    /// window bail out instead of deadlocking after a reset.
    aborted: std.atomic.Value(bool) = .init(false),
    /// Set when a GOAWAY with a lower last-stream-id refuses this stream: it was
    /// not processed by the peer and is safe to retry. Surfaced to the caller as
    /// one Event.goaway, then the stream ends. Guarded by recv_mu.
    goaway_refused: bool = false,
    goaway_delivered: bool = false,
    /// Concurrency-slot accounting (peer MAX_CONCURRENT_STREAMS), guarded by
    /// client.admit_mu. The slot is freed once both half-close directions are
    /// seen (or the stream is reset/abandoned), exactly once.
    adm_local_end: bool = false,
    adm_remote_end: bool = false,
    admit_released: bool = false,

    /// Sends `data` as flow-controlled DATA frames; `end_stream` half-closes.
    /// Blocks while the send window is empty; errors on reset/teardown.
    pub fn send(self: *Stream, data: []const u8, end_stream: bool) !void {
        const c = self.client;
        c.beginOp();
        defer c.endOp();
        if (data.len == 0) {
            if (end_stream) {
                try c.writeData(self.id, "", true);
                c.noteEnd(self, true, false); // local half-closed
            }
            return;
        }
        var off: usize = 0;
        while (off < data.len) {
            c.send_mu.lockUncancelable(c.io);
            const n = blk: while (true) {
                if (c.dead.load(.acquire)) {
                    c.send_mu.unlock(c.io);
                    return error.ConnectionClosed;
                }
                if (self.aborted.load(.acquire)) {
                    c.send_mu.unlock(c.io);
                    return error.StreamReset;
                }
                if (self.send_window <= 0) {
                    c.send_cond.waitUncancelable(c.io, &c.send_mu);
                    continue;
                }
                const avail = @min(self.send_window, c.conn_send_window);
                if (avail <= 0) {
                    c.send_cond.waitUncancelable(c.io, &c.send_mu);
                    continue;
                }
                const want: i64 = @min(@as(i64, @intCast(data.len - off)), @min(avail, @as(i64, @intCast(c.peer_max_frame.load(.acquire)))));
                self.send_window -= want;
                c.conn_send_window -= want;
                break :blk @as(usize, @intCast(want));
            };
            c.send_mu.unlock(c.io);
            const last = off + n == data.len;
            try c.writeData(self.id, data[off .. off + n], end_stream and last);
            off += n;
        }
        if (end_stream) c.noteEnd(self, true, false); // local half-closed
    }

    /// Reads the next event on this stream, blocking until one is available.
    /// Decoded headers / copied DATA are owned by `arena`. Returns
    /// `error.EndOfStream` once the peer has half-closed and the queue drains,
    /// `error.ConnectionClosed` when the connection tears down.
    pub fn readEvent(self: *Stream, arena: std.mem.Allocator) !Event {
        const c = self.client;
        c.beginOp();
        defer c.endOp();
        // Credit the flow-control window for a consumed DATA item only after
        // releasing recv_mu (defers run LIFO, so this runs after the unlock
        // below) — replenish takes write_mu, and holding recv_mu across it would
        // risk a lock cycle with deliver/openStream.
        var credit: u32 = 0;
        defer if (credit > 0) c.replenish(self.id, credit);
        self.recv_mu.lockUncancelable(c.io);
        defer self.recv_mu.unlock(c.io);
        while (true) {
            // A local cancel() takes priority: return promptly (dropping any
            // buffered items) so a blocked reader wakes the moment another
            // thread cancels the stream.
            if (self.cancelled) return error.StreamCancelled;
            if (self.queue.items.len > self.q_head) {
                const bytes = self.queue.items[self.q_head];
                const end_stream = self.end_flags.items[self.q_head];
                const is_hdr = self.is_headers.items[self.q_head];
                self.q_head += 1;
                if (self.q_head == self.queue.items.len) {
                    // Fully drained: reclaim the backing arrays and reset the cursor.
                    self.queue.clearRetainingCapacity();
                    self.end_flags.clearRetainingCapacity();
                    self.is_headers.clearRetainingCapacity();
                    self.q_head = 0;
                }
                if (is_hdr) {
                    const hs = bytes.headers;
                    const out = try arena.alloc(Header, hs.len);
                    for (hs, 0..) |h, i| {
                        out[i] = .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) };
                    }
                    freeHeaders(c.gpa, hs);
                    return .{ .headers = .{ .sid = self.id, .headers = out, .end_stream = end_stream } };
                } else {
                    const out = try arena.dupe(u8, bytes.data.bytes);
                    c.gpa.free(bytes.data.bytes);
                    credit = bytes.data.fc_cost;
                    return .{ .data = .{ .sid = self.id, .payload = out, .end_stream = end_stream } };
                }
            }
            if (self.reset != null) {
                // Surface the reset once as an event; any later call ends the
                // stream so a "readEvent until EndOfStream" loop terminates
                // instead of blocking forever.
                if (!self.rst_delivered) {
                    self.rst_delivered = true;
                    return .{ .rst = .{ .sid = self.id, .code = self.reset.? } };
                }
                return error.EndOfStream;
            }
            if (self.goaway_refused) {
                // The peer's GOAWAY refused this (unprocessed) stream: surface it
                // once as Event.goaway, then end so a drain loop terminates.
                if (!self.goaway_delivered) {
                    self.goaway_delivered = true;
                    return .goaway;
                }
                return error.EndOfStream;
            }
            if (c.dead.load(.acquire)) return error.ConnectionClosed;
            if (self.remote_closed) return error.EndOfStream;
            self.recv_cond.waitUncancelable(c.io, &self.recv_mu);
        }
    }

    /// Cancels the stream: wakes any local reader/sender, then sends
    /// RST_STREAM(CANCEL) so the peer tears down its half. Safe to call from
    /// another thread than the one blocked in `readEvent`/`send`. Stop using
    /// the stream afterwards.
    pub fn cancel(self: *Stream) !void {
        const c = self.client;
        // Wake local waiters first, so a blocked readEvent/send returns
        // promptly even if writeFrame below blocks or fails.
        self.abortLocal();
        c.noteEnd(self, true, true); // reset closes both directions
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, @intFromEnum(p2.ErrorCode.cancel), .big);
        try c.writeFrame(.rst_stream, 0, self.id, &p);
    }

    /// Marks the stream locally cancelled and wakes a blocked `readEvent`
    /// (via `recv_cond`) and a blocked `send` (via `aborted` + `send_cond`).
    /// Touches no wire; idempotent and callable from any thread.
    fn abortLocal(self: *Stream) void {
        const c = self.client;
        self.aborted.store(true, .release);
        self.recv_mu.lockUncancelable(c.io);
        self.cancelled = true;
        self.recv_cond.broadcast(c.io);
        self.recv_mu.unlock(c.io);
        c.send_cond.broadcast(c.io);
    }

    /// Releases the stream: deregisters it from the client and frees it.
    ///
    /// Call this once you are done with a stream — a completed stream is NOT
    /// reclaimed automatically (the caller still holds this `*Stream`), so
    /// without `close` every opened stream lives until `Client.deinit`, which
    /// leaks memory on a long-lived connection (a gRPC channel, a CDN origin
    /// pool). If the stream has not ended yet, `close` first sends
    /// RST_STREAM(CANCEL) so the peer tears down its half.
    ///
    /// After `close` returns, `self` is invalid — do not touch the stream (and
    /// do not `close` it twice, or race it with `readEvent`/`send` on the same
    /// stream).
    pub fn close(self: *Stream) void {
        const c = self.client;
        self.recv_mu.lockUncancelable(c.io);
        const ended = self.remote_closed or self.reset != null or self.cancelled;
        self.recv_mu.unlock(c.io);
        if (!ended and !c.dead.load(.acquire)) self.cancel() catch {};
        c.removeStream(self.id);
    }

    /// Wakes a blocked `readEvent` (after teardown or reset).
    fn shutdown(self: *Stream, io: Io) void {
        self.recv_mu.lockUncancelable(io);
        self.recv_cond.broadcast(io);
        self.recv_mu.unlock(io);
    }

    /// Frees everything still buffered on this stream. Items before `q_head`
    /// were already consumed (and freed) by `readEvent`, so only `[q_head..]`
    /// remains to free.
    fn freeQueued(self: *Stream, gpa: std.mem.Allocator) void {
        for (self.queue.items[self.q_head..], self.is_headers.items[self.q_head..]) |item, is_hdr| {
            if (is_hdr) freeHeaders(gpa, item.headers) else gpa.free(item.data.bytes);
        }
        self.queue.deinit(gpa);
        self.end_flags.deinit(gpa);
        self.is_headers.deinit(gpa);
    }

    /// Sum of the flow-control cost of DATA still buffered (from `q_head`) — the
    /// connection window we owe the peer back if the stream is torn down before
    /// the caller consumes it.
    fn unconsumedFcCost(self: *const Stream) u32 {
        var sum: u32 = 0;
        for (self.queue.items[self.q_head..], self.is_headers.items[self.q_head..]) |item, is_hdr| {
            if (!is_hdr) sum += item.data.fc_cost;
        }
        return sum;
    }
};

pub const Client = struct {
    io: Io,
    gpa: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    dec: hpack.Decoder,
    cfg: Config = .{},
    next_id: u31 = 1,
    /// Peer's SETTINGS_MAX_FRAME_SIZE. Written by the reader thread on SETTINGS
    /// and read by caller threads sizing DATA frames in `Stream.send`, so it is
    /// atomic — the same reader-writes/worker-reads pattern as the server's
    /// `Settings.max_frame_size`.
    peer_max_frame: std.atomic.Value(u32) = .init(16384),
    /// Peer's advertised SETTINGS_INITIAL_WINDOW_SIZE. Written by the reader
    /// thread (applyInitialWindow) and read by opener threads (openStream), so
    /// it is atomic to avoid a data race on that cross-thread read.
    peer_initial_window: std.atomic.Value(u32) = .init(@intCast(p2.default_window)),

    write_mu: Io.Mutex = .init,

    // Send-side flow control (connection + per-stream windows live here).
    send_mu: Io.Mutex = .init,
    send_cond: Io.Condition = .init,
    conn_send_window: i64 = p2.default_window,

    // Inbound (receive) flow control, connection level: every DATA frame is
    // deducted in full (padding included) on arrival and credited back only as
    // the caller consumes it. A window gone negative means the peer ignored
    // the window we advertised — a connection FLOW_CONTROL_ERROR (RFC 7540
    // §6.9). `fc_mu` is a leaf lock; when nested, taken under streams_mu only.
    fc_mu: Io.Mutex = .init,
    conn_recv_window: i64 = p2.default_window,

    streams_mu: Io.Mutex = .init,
    streams: std.AutoHashMapUnmanaged(u31, *Stream) = .empty,

    // In-flight readEvent/send accounting. `deinit` waits for this to drain so
    // it never frees a *Stream while a user thread (e.g. a bidi send/receive
    // thread) is still inside readEvent/send on it (use-after-free).
    op_mu: Io.Mutex = .init,
    op_cond: Io.Condition = .init,
    active_ops: u32 = 0,

    // Outbound-stream admission (peer SETTINGS_MAX_CONCURRENT_STREAMS). openStream
    // blocks here until a slot frees. Both fields are guarded by admit_mu.
    admit_mu: Io.Mutex = .init,
    admit_cond: Io.Condition = .init,
    peer_max_streams: u32 = std.math.maxInt(u32), // "unlimited" until advertised
    active_streams: u32 = 0,

    keepalive_time_ms: u64 = 0,
    keepalive_timeout_ms: u64 = 0,
    ping_outstanding: bool = false,

    dead: std.atomic.Value(bool) = .init(false),
    reader_thread: ?std.Thread = null,

    // Graceful GOAWAY state. `goaway_seen` gates it (release/acquire); the two
    // fields are written once by the reader before the flag is set.
    goaway_seen: std.atomic.Value(bool) = .init(false),
    goaway_last_id: u31 = 0,
    goaway_code: u32 = 0,

    const TimedHeader = union(enum) { work: anyerror!void, timer: void };

    /// Sends the connection preface + empty SETTINGS and starts the reader.
    /// Takes `self` by pointer so the reader thread has a stable address.
    pub fn init(self: *Client, io: Io, gpa: std.mem.Allocator, r: *Io.Reader, w: *Io.Writer) !void {
        return self.initWithConfig(io, gpa, r, w, .{});
    }

    /// As `init`, with explicit flow-control tuning. See `Config`.
    pub fn initWithConfig(self: *Client, io: Io, gpa: std.mem.Allocator, r: *Io.Reader, w: *Io.Writer, cfg: Config) !void {
        const cwnd = p2.clampConnWindow(cfg.connection_window_size);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .r = r,
            .w = w,
            .dec = hpack.Decoder.init(gpa, p2.our_header_table_size),
            .cfg = cfg,
            .conn_recv_window = cwnd,
        };
        try self.w.writeAll(p2.preface);
        // Advertise SETTINGS_ENABLE_PUSH=0 (we don't implement PUSH_PROMISE),
        // SETTINGS_MAX_FRAME_SIZE=16384 (the largest inbound frame we accept),
        // and the per-stream window we are prepared to receive into.
        var settings: [18]u8 = undefined;
        p2.putSetting(settings[0..6], p2.set_enable_push, 0);
        p2.putSetting(settings[6..12], p2.set_max_frame_size, max_recv_frame);
        p2.putSetting(settings[12..18], p2.set_initial_window_size, @intCast(p2.clampInitialWindow(cfg.initial_window_size)));
        try self.writeFrame(.settings, 0, 0, &settings);
        // The connection window is the one thing SETTINGS cannot carry: it is
        // fixed at 65535 and only ever grows by WINDOW_UPDATE (RFC 7540 §6.9.2).
        if (cwnd > p2.default_window) {
            self.windowUpdate(0, @intCast(cwnd - p2.default_window));
        }
        self.reader_thread = std.Thread.spawn(.{}, readerLoop, .{self}) catch return error.SystemResources;
    }

    /// If the peer has sent a GOAWAY, returns its last-processed stream id and
    /// error code; null otherwise. Streams with a higher id were not processed
    /// and are safe to retry on a fresh connection.
    pub fn goAway(self: *Client) ?struct { last_stream_id: u31, code: u32 } {
        if (!self.goaway_seen.load(.acquire)) return null;
        return .{ .last_stream_id = self.goaway_last_id, .code = self.goaway_code };
    }

    /// Releases the client: stops the reader thread, waits for in-flight
    /// readEvent/send to drain, then frees all streams.
    ///
    /// ⚠️ The reader thread blocks in an I/O read on `r`; `dead`+broadcast wake
    /// cond-waiters but NOT an I/O-blocked read. So the reader only exits when
    /// that read returns — i.e. when the **transport is closed** (EOF/error) or
    /// keepalive PINGs periodically wake it. **The caller must close the
    /// transport around `deinit`** (e.g. close the socket for `connectTcp`, or
    /// the custom Reader's underlying fd for `Channel.init`). Without this,
    /// `reader_thread.join` blocks indefinitely on a persistent connection.
    pub fn deinit(self: *Client) void {
        // Tell the reader to stop, then wake any blocked senders/readers so they
        // observe `dead` and return. (This wakes cond-waiters; the I/O-blocked
        // reader still needs the transport closed by the caller — see doc above.)
        self.dead.store(true, .release);
        self.send_cond.broadcast(self.io);
        self.admit_cond.broadcast(self.io); // release a blocked openStream
        self.streams_mu.lockUncancelable(self.io);
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.*.shutdown(self.io);
        self.streams_mu.unlock(self.io);
        if (self.reader_thread) |t| t.join();

        // Wait for any user thread still inside readEvent/send (which we just
        // woke) to release its *Stream before we free them. Callers must not
        // start new readEvent/send calls once deinit has begun.
        self.op_mu.lockUncancelable(self.io);
        while (self.active_ops != 0) self.op_cond.waitUncancelable(self.io, &self.op_mu);
        self.op_mu.unlock(self.io);

        self.dec.deinit();
        var it2 = self.streams.valueIterator();
        while (it2.next()) |s| {
            s.*.freeQueued(self.gpa);
            self.gpa.destroy(s.*);
        }
        self.streams.deinit(self.gpa);
    }

    /// Records that a stream reached one/both half-close directions and frees
    /// its concurrency slot once both are seen (RFC 7540 §5.1.2). Idempotent.
    fn noteEnd(self: *Client, s: *Stream, local: bool, remote: bool) void {
        self.admit_mu.lockUncancelable(self.io);
        if (local) s.adm_local_end = true;
        if (remote) s.adm_remote_end = true;
        if (!s.admit_released and s.adm_local_end and s.adm_remote_end) {
            s.admit_released = true;
            self.active_streams -= 1;
            self.admit_cond.broadcast(self.io);
        }
        self.admit_mu.unlock(self.io);
    }

    /// Frees a stream's slot unconditionally (backstop for a stream removed
    /// before it reached the closed state). Idempotent via `admit_released`.
    fn releaseSlot(self: *Client, s: *Stream) void {
        self.admit_mu.lockUncancelable(self.io);
        if (!s.admit_released) {
            s.admit_released = true;
            self.active_streams -= 1;
            self.admit_cond.broadcast(self.io);
        }
        self.admit_mu.unlock(self.io);
    }

    /// Registers entry into a user-facing stream op (readEvent/send). Paired
    /// with `endOp`; `deinit` blocks until the count returns to zero.
    fn beginOp(self: *Client) void {
        self.op_mu.lockUncancelable(self.io);
        self.active_ops += 1;
        self.op_mu.unlock(self.io);
    }

    fn endOp(self: *Client) void {
        self.op_mu.lockUncancelable(self.io);
        self.active_ops -= 1;
        if (self.active_ops == 0) self.op_cond.broadcast(self.io);
        self.op_mu.unlock(self.io);
    }

    fn writeFrameLocked(self: *Client, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        var hb: [9]u8 = undefined;
        p2.putHeader(&hb, payload.len, ftype, flags, sid);
        try self.w.writeAll(&hb);
        if (payload.len > 0) try self.w.writeAll(payload);
    }

    fn writeFrame(self: *Client, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        self.write_mu.lockUncancelable(self.io);
        defer self.write_mu.unlock(self.io);
        try self.writeFrameLocked(ftype, flags, sid, payload);
        try self.w.flush();
    }

    fn writeData(self: *Client, sid: u31, data: []const u8, end_stream: bool) !void {
        const flags: u8 = if (end_stream) p2.flag_end_stream else 0;
        try self.writeFrame(.data, flags, sid, data);
    }

    /// Best-effort GOAWAY(last_stream_id=0, code). The client only observes
    /// peer-initiated (even/push) streams — disabled — so the last id is 0.
    fn sendGoaway(self: *Client, code: p2.ErrorCode) void {
        var p: [8]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], 0, .big);
        std.mem.writeInt(u32, p[4..8], @intFromEnum(code), .big);
        self.writeFrame(.goaway, 0, 0, &p) catch {};
    }

    /// Opens a new stream, sending the request HEADERS. Returns a handle for
    /// send/readEvent/cancel. `end_stream` half-closes immediately (bodyless).
    /// The stream id is allocated and HEADERS emitted under `write_mu` so that
    /// concurrent openers issue ids in strictly increasing wire order (RFC 7540
    /// §5.1.1); the stream is registered before HEADERS is sent so the reader
    /// can deliver the response.
    pub fn openStream(self: *Client, head: RequestHead, end_stream: bool) !*Stream {
        var tmp = std.heap.ArenaAllocator.init(self.gpa);
        defer tmp.deinit();
        var block: std.ArrayList(u8) = .empty;
        try hpack.Encoder.encodeRequest(tmp.allocator(), &block, head.method, head.scheme, head.path, head.authority, head.headers);

        // Admission: block until a concurrency slot is free (peer
        // MAX_CONCURRENT_STREAMS), or bail if the connection is closing.
        self.admit_mu.lockUncancelable(self.io);
        while (true) {
            if (self.dead.load(.acquire)) {
                self.admit_mu.unlock(self.io);
                return error.ConnectionClosed;
            }
            if (self.goaway_seen.load(.acquire)) {
                self.admit_mu.unlock(self.io);
                return error.GoingAway;
            }
            if (self.active_streams < self.peer_max_streams) break;
            self.admit_cond.waitUncancelable(self.io, &self.admit_mu);
        }
        self.active_streams += 1;
        self.admit_mu.unlock(self.io);

        self.write_mu.lockUncancelable(self.io);
        const sid = self.next_id;
        self.next_id = std.math.add(u31, sid, 2) catch {
            self.write_mu.unlock(self.io);
            self.admitCancel();
            return error.StreamIdsExhausted;
        };

        const st = self.gpa.create(Stream) catch {
            self.write_mu.unlock(self.io);
            self.admitCancel();
            return error.OutOfMemory;
        };
        // The receive window must match the SETTINGS_INITIAL_WINDOW_SIZE we
        // advertised, or our ledger disagrees with the peer's from the start.
        st.* = .{ .client = self, .id = sid, .send_window = 0, .recv_window = p2.clampInitialWindow(self.cfg.initial_window_size) };
        self.streams_mu.lockUncancelable(self.io);
        // Seed the send window under streams_mu, which applyInitialWindow also
        // holds while it rewrites peer_initial_window and shifts every
        // registered stream. Reading it outside the lock let a concurrent
        // SETTINGS land in between, so the new stream picked up neither the new
        // value nor the delta and ran with a stale window.
        st.send_window = self.peer_initial_window.load(.acquire);
        self.streams.put(self.gpa, sid, st) catch {
            self.streams_mu.unlock(self.io);
            self.write_mu.unlock(self.io);
            self.releaseSlot(st);
            self.gpa.destroy(st);
            return error.OutOfMemory;
        };
        self.streams_mu.unlock(self.io);

        // Emit HEADERS (plus CONTINUATION when the block exceeds the peer's
        // SETTINGS_MAX_FRAME_SIZE, RFC 7540 §6.2) atomically under write_mu,
        // mirroring the server's writeHeaders: a single oversized HEADERS
        // frame is a FRAME_SIZE_ERROR to any spec-compliant peer. END_STREAM
        // rides the HEADERS frame, END_HEADERS the last fragment.
        const es: u8 = if (end_stream) p2.flag_end_stream else 0;
        const max: usize = self.peer_max_frame.load(.acquire);
        if (block.items.len > max_header_block) {
            // Same bound the server enforces inbound; past it a huge block
            // could also overflow putHeader's 24-bit length field.
            self.write_mu.unlock(self.io);
            self.removeStream(sid); // releases the slot
            return error.HeadersTooLarge;
        }
        if (block.items.len <= max) {
            self.writeFrameLocked(.headers, p2.flag_end_headers | es, sid, block.items) catch {
                self.write_mu.unlock(self.io);
                self.removeStream(sid); // releases the slot
                return error.ConnectionClosed;
            };
        } else {
            self.writeFrameLocked(.headers, es, sid, block.items[0..max]) catch {
                self.write_mu.unlock(self.io);
                self.removeStream(sid); // releases the slot
                return error.ConnectionClosed;
            };
            var off: usize = max;
            while (off < block.items.len) {
                const end = @min(off + max, block.items.len);
                const last = end == block.items.len;
                self.writeFrameLocked(.continuation, if (last) p2.flag_end_headers else 0, sid, block.items[off..end]) catch {
                    self.write_mu.unlock(self.io);
                    self.removeStream(sid); // releases the slot
                    return error.ConnectionClosed;
                };
                off = end;
            }
        }
        self.w.flush() catch {
            self.write_mu.unlock(self.io);
            self.removeStream(sid);
            return error.ConnectionClosed;
        };
        self.write_mu.unlock(self.io);
        // A bodyless request half-closes our side immediately.
        if (end_stream) self.noteEnd(st, true, false);
        return st;
    }

    /// Undoes an admission reservation on an openStream failure that happens
    /// before a *Stream exists to carry the `admit_released` flag.
    fn admitCancel(self: *Client) void {
        self.admit_mu.lockUncancelable(self.io);
        self.active_streams -= 1;
        self.admit_cond.broadcast(self.io);
        self.admit_mu.unlock(self.io);
    }

    fn removeStream(self: *Client, sid: u31) void {
        self.streams_mu.lockUncancelable(self.io);
        if (self.streams.fetchRemove(sid)) |kv| {
            self.streams_mu.unlock(self.io);
            // Return the connection window for any DATA the caller never
            // consumed, so tearing streams down doesn't leak it (only while the
            // connection is still live — a dead peer needs no credit). The
            // ledger must grow with the credit granted, same as replenish.
            const owed = kv.value.unconsumedFcCost();
            self.releaseSlot(kv.value); // backstop: free the slot if not already
            kv.value.freeQueued(self.gpa);
            self.gpa.destroy(kv.value);
            if (!self.dead.load(.acquire)) {
                if (owed > 0) {
                    self.fc_mu.lockUncancelable(self.io);
                    self.conn_recv_window += @as(i64, owed);
                    self.fc_mu.unlock(self.io);
                }
                self.windowUpdate(0, owed);
            }
        } else {
            self.streams_mu.unlock(self.io);
        }
    }

    // --- reader thread ------------------------------------------------------

    fn readerLoop(self: *Client) void {
        while (!self.dead.load(.acquire)) {
            var hb: [9]u8 = undefined;
            self.readFrameHeader(&hb) catch {
                self.kill();
                return;
            };
            const fh = p2.parseHeader(&hb);
            if (fh.length > max_recv_frame) {
                self.sendGoaway(.frame_size_error);
                self.kill();
                return;
            }
            const payload = self.gpa.alloc(u8, fh.length) catch {
                self.kill();
                return;
            };
            defer self.gpa.free(payload);
            if (payload.len > 0) {
                self.r.readSliceAll(payload) catch {
                    self.kill();
                    return;
                };
            }
            // Same framing rules as the server (SETTINGS sid/length, PING
            // length, WINDOW_UPDATE length, DATA/HEADERS on stream 0, ...):
            // a violation is a connection error (RFC 7540 §4/§6), so GOAWAY
            // rather than mis-handle the frame.
            if (p2.validateInboundFrame(fh, payload)) |code| {
                self.sendGoaway(code);
                self.kill();
                return;
            }
            self.handle(fh, payload) catch {
                self.kill();
                return;
            };
        }
    }

    /// Marks the connection dead and releases every blocked stream/sender.
    fn kill(self: *Client) void {
        self.dead.store(true, .release);
        self.send_cond.broadcast(self.io);
        self.admit_cond.broadcast(self.io); // release a blocked openStream
        self.streams_mu.lockUncancelable(self.io);
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.*.shutdown(self.io);
        self.streams_mu.unlock(self.io);
    }

    fn handle(self: *Client, fh: p2.ParsedHeader, payload: []const u8) !void {
        switch (fh.ftype) {
            .settings => if (fh.flags & p2.flag_ack == 0) {
                try self.applyPeerSettings(payload);
                try self.writeFrame(.settings, p2.flag_ack, 0, "");
            },
            .ping => if (fh.flags & p2.flag_ack == 0) try self.writeFrame(.ping, p2.flag_ack, 0, payload),
            .window_update => try self.handleWindowUpdate(fh.sid, payload),
            .goaway => {
                if (payload.len < 8) {
                    self.sendGoaway(.protocol_error);
                    self.kill();
                    return error.ProtocolError;
                }
                const last_id: u31 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
                self.goaway_last_id = last_id;
                self.goaway_code = std.mem.readInt(u32, payload[4..8], .big);
                self.goaway_seen.store(true, .release);
                // Refuse only streams the peer will not process (id > last_id):
                // one Event.goaway, then the stream ends — safe to retry. Streams
                // <= last_id keep receiving. Do NOT kill: teardown happens when
                // the transport actually closes (reader hits EOF -> kill).
                self.streams_mu.lockUncancelable(self.io);
                var it = self.streams.valueIterator();
                while (it.next()) |sp| {
                    const s = sp.*;
                    if (s.id > last_id) {
                        s.aborted.store(true, .release);
                        s.recv_mu.lockUncancelable(self.io);
                        s.goaway_refused = true;
                        s.recv_cond.broadcast(self.io);
                        s.recv_mu.unlock(self.io);
                        self.noteEnd(s, true, true); // refused: frees its slot
                    }
                }
                self.streams_mu.unlock(self.io);
                self.send_cond.broadcast(self.io); // release refused senders
                self.admit_cond.broadcast(self.io); // and a blocked openStream
            },
            .rst_stream => {
                const code: u32 = if (payload.len >= 4) std.mem.readInt(u32, payload[0..4], .big) else 0;
                self.streams_mu.lockUncancelable(self.io);
                if (self.streams.get(fh.sid)) |st| {
                    st.aborted.store(true, .release);
                    st.recv_mu.lockUncancelable(self.io);
                    st.reset = code;
                    st.recv_cond.broadcast(self.io);
                    st.recv_mu.unlock(self.io);
                    self.noteEnd(st, true, true); // reset frees its slot
                }
                self.streams_mu.unlock(self.io);
                // Wake any sender blocked on this stream's flow-control window;
                // it checks `aborted` and returns error.StreamReset.
                self.send_cond.broadcast(self.io);
                self.admit_cond.broadcast(self.io);
            },
            .headers => {
                var block: std.ArrayList(u8) = .empty;
                defer block.deinit(self.gpa);
                const frag = stripHeaderPadding(fh, payload) orelse {
                    self.sendGoaway(.protocol_error);
                    self.kill();
                    return error.ProtocolError;
                };
                try block.appendSlice(self.gpa, frag);
                if (fh.flags & p2.flag_end_headers == 0) try self.readContinuations(fh.sid, &block);
                const hs = try self.dec.decode(self.gpa, block.items);
                try self.deliver(fh.sid, true, hs, &[_]u8{}, fh.flags & p2.flag_end_stream != 0, 0);
            },
            .data => {
                // Flow control counts the whole frame (pad octet + data + pad).
                // We credit it only when the caller consumes the DATA (see
                // readEvent) so an unread stream backpressures the peer.
                const fc_cost: u32 = @intCast(payload.len);
                const body = stripDataPadding(fh, payload) orelse {
                    self.sendGoaway(.protocol_error);
                    self.kill();
                    return error.ProtocolError;
                };
                // Inbound connection-level flow control: deduct the full frame
                // length on arrival. A negative window means the peer sent
                // beyond what we advertised — a connection FLOW_CONTROL_ERROR
                // (RFC 7540 §6.9), not an invitation to buffer it all.
                {
                    self.fc_mu.lockUncancelable(self.io);
                    self.conn_recv_window -= @as(i64, fc_cost);
                    const overflow = self.conn_recv_window < 0;
                    self.fc_mu.unlock(self.io);
                    if (overflow) {
                        self.sendGoaway(.flow_control_error);
                        self.kill();
                        return error.FlowControlError;
                    }
                }
                const copy = try self.gpa.dupe(u8, body);
                try self.deliver(fh.sid, false, &[_]hpack.Header{}, copy, fh.flags & p2.flag_end_stream != 0, fc_cost);
            },
            .push_promise => {
                // We advertised ENABLE_PUSH=0, so a push is a protocol
                // violation. Tolerating it is also unsafe: its header block goes
                // undecoded, desyncing HPACK for every later frame. Tear down
                // (GOAWAY first, so the peer learns why).
                self.sendGoaway(.protocol_error);
                self.kill();
                return error.ConnectionClosed;
            },
            .continuation => {
                // `readContinuations` consumes an in-sequence CONTINUATION
                // inline, so one arriving here continues nothing: a connection
                // PROTOCOL_ERROR (RFC 9113 §6.10). Ignoring it also dropped a
                // header-block fragment, desyncing HPACK for every later frame.
                self.sendGoaway(.protocol_error);
                self.kill();
                return error.ProtocolError;
            },
            else => {}, // priority
        }
    }

    /// Pushes one item onto the stream's queue (or frees it if the stream is
    /// gone). Lock order: streams_mu -> recv_mu. For DATA, also deducts the
    /// stream receive window; on overflow (or an unknown stream) the frame is
    /// a stream error — freed and RST — while the connection-level window is
    /// returned immediately, since closed streams still consume conn credit
    /// (RFC 7540 §6.9).
    fn deliver(self: *Client, sid: u31, is_headers: bool, hs: []const Header, bytes: []u8, end_stream: bool, fc_cost: u32) !void {
        self.streams_mu.lockUncancelable(self.io);
        const st = self.streams.get(sid);
        if (st) |s| {
            s.recv_mu.lockUncancelable(self.io);
            const item: Queued = if (is_headers) .{ .headers = hs } else .{ .data = .{ .bytes = bytes, .fc_cost = fc_cost } };
            var rst: ?p2.ErrorCode = null;
            if (!is_headers) {
                s.recv_window -= @as(i64, fc_cost);
                if (s.recv_window < 0) {
                    // Peer sent beyond the stream window we track: a stream
                    // FLOW_CONTROL_ERROR. Drop the frame and reset the stream
                    // (its queued DATA is freed by readEvent's reset path or
                    // removeStream), keeping the connection.
                    s.recv_window += @as(i64, fc_cost); // nothing delivered: no stream credit owed
                    rst = .flow_control_error;
                }
            }
            if (rst == null) {
                var oom = false;
                s.queue.append(self.gpa, item) catch {
                    oom = true;
                };
                if (!oom) {
                    s.end_flags.append(self.gpa, end_stream) catch {
                        s.queue.items.len -= 1;
                        oom = true;
                    };
                }
                if (!oom) {
                    s.is_headers.append(self.gpa, is_headers) catch {
                        s.queue.items.len -= 1;
                        s.end_flags.items.len -= 1;
                        oom = true;
                    };
                }
                if (oom) {
                    if (is_headers) freeHeaders(self.gpa, hs) else self.gpa.free(bytes);
                    s.recv_mu.unlock(self.io);
                    self.streams_mu.unlock(self.io);
                    return error.OutOfMemory;
                }
            } else {
                if (is_headers) freeHeaders(self.gpa, hs) else self.gpa.free(bytes);
            }
            if (rst) |code| {
                s.aborted.store(true, .release);
                s.reset = @intFromEnum(code);
                s.recv_cond.broadcast(self.io);
                s.recv_mu.unlock(self.io);
                self.noteEnd(s, true, true); // reset frees its slot
                self.streams_mu.unlock(self.io);
                self.send_cond.broadcast(self.io); // release a sender blocked on the window
                var p: [4]u8 = undefined;
                std.mem.writeInt(u32, &p, @intFromEnum(code), .big);
                self.writeFrame(.rst_stream, 0, sid, &p) catch {};
                // The frame is dropped: return the connection window we
                // deducted on arrival, and keep our ledger in step with the
                // credit we grant (RFC 7540 §6.9 — conn flow control spans
                // reset/closed streams).
                {
                    self.fc_mu.lockUncancelable(self.io);
                    self.conn_recv_window += @as(i64, fc_cost);
                    self.fc_mu.unlock(self.io);
                }
                self.windowUpdate(0, fc_cost);
                return;
            }
            if (end_stream) s.remote_closed = true;
            s.recv_cond.broadcast(self.io);
            s.recv_mu.unlock(self.io);
            if (end_stream) self.noteEnd(s, false, true); // remote half-closed
            self.streams_mu.unlock(self.io);
        } else {
            self.streams_mu.unlock(self.io);
            if (is_headers) {
                freeHeaders(self.gpa, hs);
            } else {
                self.gpa.free(bytes);
                // DATA on an id above the highest we ever allocated (next_id
                // is the next to hand out) is DATA on an idle stream: a
                // connection PROTOCOL_ERROR (RFC 9113 §5.1), the same rule the
                // server enforces — GOAWAY, and the reader tears us down.
                // next_id is written under write_mu, so read it under it too.
                self.write_mu.lockUncancelable(self.io);
                const idle = sid >= self.next_id;
                self.write_mu.unlock(self.io);
                if (idle) {
                    self.sendGoaway(.protocol_error);
                    return error.ProtocolError;
                }
                // An id at or below it that is not open was closed: a stream
                // error — RST STREAM_CLOSED, keeping the connection.
                var p: [4]u8 = undefined;
                std.mem.writeInt(u32, &p, @intFromEnum(p2.ErrorCode.stream_closed), .big);
                self.writeFrame(.rst_stream, 0, sid, &p) catch {};
            }
            // Stream already gone, but the connection window must still be
            // returned for its DATA (RFC 7540 §6.9 — conn flow control spans
            // closed streams), or a hostile peer could leak it to zero. The
            // ledger grows with the credit granted, same as replenish.
            if (fc_cost > 0) {
                self.fc_mu.lockUncancelable(self.io);
                self.conn_recv_window += @as(i64, fc_cost);
                self.fc_mu.unlock(self.io);
            }
            self.windowUpdate(0, fc_cost);
        }
    }

    /// Sends a WINDOW_UPDATE crediting `amt` bytes to `sid` (0 = connection).
    fn windowUpdate(self: *Client, sid: u31, amt: u32) void {
        if (amt == 0) return;
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, amt, .big);
        self.writeFrame(.window_update, 0, sid, &wu) catch {};
    }

    /// Credits both the connection and the stream window for `amt` bytes of
    /// consumed DATA, reopening the peer's send window. The stream-level
    /// increment is capped so the window never exceeds 2^31-1 (RFC 7540
    /// §6.9.1) — a peer that pads every frame could otherwise grow it without
    /// bound, one small replenish at a time.
    fn replenish(self: *Client, sid: u31, amt: u32) void {
        if (amt == 0) return;
        {
            // Our own connection-window ledger must grow with the credit we
            // grant, or the next 65535 inbound bytes would look like an
            // overflow even though everything was consumed.
            self.fc_mu.lockUncancelable(self.io);
            self.conn_recv_window += @as(i64, amt);
            self.fc_mu.unlock(self.io);
        }
        var stream_amt: u32 = amt;
        self.streams_mu.lockUncancelable(self.io);
        const st = self.streams.get(sid);
        if (st) |s| {
            s.recv_mu.lockUncancelable(self.io);
            const room: i64 = 0x7fff_ffff - s.recv_window;
            if (room < @as(i64, amt)) stream_amt = if (room > 0) @intCast(room) else 0;
            if (stream_amt > 0) s.recv_window += @intCast(stream_amt);
            s.recv_mu.unlock(self.io);
        }
        self.streams_mu.unlock(self.io);
        self.windowUpdate(0, amt); // connection
        if (stream_amt > 0) self.windowUpdate(sid, stream_amt); // stream
    }

    fn handleWindowUpdate(self: *Client, sid: u31, payload: []const u8) !void {
        // Length == 4 is guaranteed by proto.validateInboundFrame before dispatch.
        const incr: i64 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
        // A 0 increment is a PROTOCOL_ERROR: connection-level is fatal, stream
        // level resets just that stream (RFC 7540 §6.9).
        if (incr == 0) {
            if (sid == 0) {
                self.sendGoaway(.protocol_error);
                return error.ProtocolError;
            }
            var p: [4]u8 = undefined;
            std.mem.writeInt(u32, &p, @intFromEnum(p2.ErrorCode.protocol_error), .big);
            self.writeFrame(.rst_stream, 0, sid, &p) catch {};
            return;
        }
        var overflow_sid: ?u31 = null;
        {
            self.streams_mu.lockUncancelable(self.io);
            defer self.streams_mu.unlock(self.io);
            self.send_mu.lockUncancelable(self.io);
            defer self.send_mu.unlock(self.io);
            if (sid == 0) {
                if (self.conn_send_window + incr > 0x7fff_ffff) return error.FlowControlError;
                self.conn_send_window += incr;
            } else if (self.streams.get(sid)) |st| {
                if (st.send_window + incr > 0x7fff_ffff) {
                    // Stream overflow: reset just that stream (RFC 7540 §6.9.1).
                    // Defer the RST_STREAM write until the locks are released.
                    st.send_window = 0;
                    overflow_sid = sid;
                } else {
                    st.send_window += incr;
                }
            }
            self.send_cond.broadcast(self.io);
        }
        // Send the reset outside streams_mu/send_mu: writeFrame takes write_mu,
        // and openStream takes write_mu -> streams_mu, so holding streams_mu
        // across write_mu here would be a lock-order inversion (deadlock).
        if (overflow_sid) |osid| {
            var p: [4]u8 = undefined;
            std.mem.writeInt(u32, &p, @intFromEnum(p2.ErrorCode.flow_control_error), .big);
            self.writeFrame(.rst_stream, 0, osid, &p) catch {};
        }
    }

    fn applyPeerSettings(self: *Client, payload: []const u8) !void {
        var i: usize = 0;
        var new_iw: ?u32 = null;
        while (i + 6 <= payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            switch (id) {
                p2.set_max_frame_size => {
                    // Outside [2^14, 2^24-1] is a connection PROTOCOL_ERROR
                    // (RFC 7540 §6.5.2); ignoring the value would keep the
                    // connection alive against an oversized frame we may then
                    // read (or a tiny frame size wedging our sender).
                    if (val < 16384 or val > 16777215) {
                        self.sendGoaway(.protocol_error);
                        return error.ProtocolError;
                    }
                    self.peer_max_frame.store(val, .release);
                },
                p2.set_initial_window_size => {
                    if (val > 0x7fff_ffff) {
                        self.sendGoaway(.flow_control_error);
                        return error.FlowControlError;
                    }
                    new_iw = val;
                },
                p2.set_max_concurrent_streams => {
                    self.admit_mu.lockUncancelable(self.io);
                    self.peer_max_streams = val;
                    self.admit_cond.broadcast(self.io); // a raised limit wakes waiters
                    self.admit_mu.unlock(self.io);
                },
                else => {},
            }
        }
        if (new_iw) |iw| try self.applyInitialWindow(iw);
    }

    /// Shift every live stream's send window by the SETTINGS_INITIAL_WINDOW_SIZE
    /// delta (RFC 7540 §6.9.2). Lock order: streams_mu -> send_mu. Returns
    /// error.FlowControlError (after GOAWAY) when the shift pushes any window
    /// past 2^31-1 — a connection FLOW_CONTROL_ERROR (RFC 7540 §6.9.2).
    fn applyInitialWindow(self: *Client, new_iw: u32) !void {
        var overflow = false;
        {
            self.streams_mu.lockUncancelable(self.io);
            defer self.streams_mu.unlock(self.io);
            self.send_mu.lockUncancelable(self.io);
            defer self.send_mu.unlock(self.io);
            const delta: i64 = @as(i64, new_iw) - @as(i64, self.peer_initial_window.load(.acquire));
            self.peer_initial_window.store(new_iw, .release);
            if (delta != 0) {
                var it = self.streams.valueIterator();
                while (it.next()) |s| {
                    // Each window is <= 2^31-1 and |delta| < 2^31, so the sum
                    // cannot overflow i64; a result over 2^31-1 is the illegal
                    // state itself.
                    s.*.send_window += delta;
                    if (s.*.send_window > 0x7fff_ffff) overflow = true;
                }
                self.send_cond.broadcast(self.io);
            }
        }
        // GOAWAY only after the locks drop: sendGoaway takes write_mu, and
        // openStream holds write_mu while waiting on streams_mu, so GOAWAYing
        // under streams_mu inverts that order (deadlock) — same reasoning as
        // the deferred RST in handleWindowUpdate.
        if (overflow) {
            self.sendGoaway(.flow_control_error);
            return error.FlowControlError;
        }
    }

    fn readContinuations(self: *Client, sid: u31, block: *std.ArrayList(u8)) !void {
        var frames: usize = 0;
        while (true) {
            var hb: [9]u8 = undefined;
            try self.r.readSliceAll(&hb);
            const cf = p2.parseHeader(&hb);
            if (cf.ftype != .continuation or cf.sid != sid) {
                // A header block must not be interleaved with any other frame
                // (RFC 9113 §6.10) — a connection error, so say so on the wire
                // rather than just dropping the connection.
                self.sendGoaway(.protocol_error);
                return error.ProtocolError;
            }
            if (cf.length > max_recv_frame) {
                self.sendGoaway(.frame_size_error);
                return error.FrameSizeError;
            }
            frames += 1;
            if (frames > max_continuation_frames) {
                // Zero-length CONTINUATIONs never grow `block`, so the byte cap
                // below cannot stop an endless stream of them; cap the count.
                self.sendGoaway(.enhance_your_calm);
                return error.ProtocolError;
            }
            if (block.items.len + cf.length > max_header_block) {
                self.sendGoaway(.enhance_your_calm);
                return error.ProtocolError;
            }
            const cp = try self.gpa.alloc(u8, cf.length);
            defer self.gpa.free(cp);
            if (cp.len > 0) try self.r.readSliceAll(cp);
            try block.appendSlice(self.gpa, cp);
            if (cf.flags & p2.flag_end_headers != 0) break;
        }
    }

    /// Reads the next 9-byte frame header, racing a deadline so `deinit` (via
    /// `dead`) and keepalive can make progress. Any inbound frame clears an
    /// outstanding keepalive probe; silence past the probe means a dead peer.
    fn readFrameHeader(self: *Client, hb: *[9]u8) !void {
        const ka = self.keepalive_time_ms != 0;
        const ms: u64 = if (ka) (if (self.ping_outstanding) self.keepalive_timeout_ms else self.keepalive_time_ms) else reader_wake_ms;
        while (true) {
            if (self.timedReadHeader(hb, ms)) {
                self.ping_outstanding = false;
                return;
            } else |err| switch (err) {
                error.Timeout => {
                    if (self.dead.load(.acquire)) return error.ConnectionClosed;
                    if (!ka) continue; // just a wake to recheck `dead`
                    if (self.ping_outstanding) {
                        self.kill();
                        return error.ConnectionClosed; // keepalive timeout: peer is dead
                    }
                    const ping = @as([8]u8, @splat(0));
                    self.writeFrame(.ping, 0, 0, &ping) catch return error.ConnectionClosed;
                    self.ping_outstanding = true;
                },
                else => return err,
            }
        }
    }

    fn readHeaderThunk(self: *Client, hb: *[9]u8) anyerror!void {
        return self.r.readSliceAll(hb);
    }

    fn keepaliveTimer(io: Io, ms: u64) void {
        Io.sleep(io, .{ .nanoseconds = @intCast(ms * std.time.ns_per_ms) }, .awake) catch {};
    }

    fn timedReadHeader(self: *Client, hb: *[9]u8, timeout_ms: u64) !void {
        var buf: [2]TimedHeader = undefined;
        var sel = Io.Select(TimedHeader).init(self.io, &buf);
        sel.concurrent(.work, readHeaderThunk, .{ self, hb }) catch return self.r.readSliceAll(hb);
        sel.concurrent(.timer, keepaliveTimer, .{ self.io, timeout_ms }) catch {
            while (sel.cancel()) |_| {}
            return self.r.readSliceAll(hb);
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
};

fn freeHeaders(gpa: std.mem.Allocator, hs: []const Header) void {
    for (hs) |h| {
        gpa.free(h.name);
        gpa.free(h.value);
    }
    gpa.free(hs);
}

/// Strips a DATA frame's PADDED prefix/suffix (RFC 7540 §6.1). Returns null if
/// the pad-length octet is missing or exceeds the remaining payload — a
/// connection PROTOCOL_ERROR — so the caller can tear down instead of
/// delivering a corrupt body.
fn stripDataPadding(fh: p2.ParsedHeader, payload: []const u8) ?[]const u8 {
    if (fh.flags & p2.flag_padded == 0) return payload;
    if (payload.len == 0) return null; // PADDED set but no pad-length octet
    const pad = payload[0];
    const rest = payload[1..];
    if (pad > rest.len) return null; // padding longer than what remains
    return rest[0 .. rest.len - pad];
}

/// Strips a HEADERS frame's PADDED/PRIORITY prefixes (RFC 9113 §6.2). Returns
/// null when a prefix does not fit the payload — a connection PROTOCOL_ERROR —
/// so the caller tears down instead of decoding what is left.
///
/// Trimming silently and decoding the remainder anyway is the same desync the
/// server side had: HPACK's dynamic table is connection-wide state, so one
/// mis-framed block leaves our table out of step with the peer's and every
/// later indexed reference resolves to the wrong field, with no error anywhere.
fn stripHeaderPadding(fh: p2.ParsedHeader, payload: []const u8) ?[]const u8 {
    var frag = payload;
    if (fh.flags & p2.flag_padded != 0) {
        if (frag.len == 0) return null; // PADDED set but no pad-length octet
        const pad = frag[0];
        frag = frag[1..];
        if (pad > frag.len) return null; // padding longer than what remains
        frag = frag[0 .. frag.len - pad];
    }
    if (fh.flags & p2.flag_priority != 0) {
        if (frag.len < 5) return null; // PRIORITY set but no room for its fields
        frag = frag[5..];
    }
    return frag;
}

// --- tests ---

const testing = std.testing;
const net = std.Io.net;

/// Accepts one connection, drains whatever the client sends, and never replies —
/// so a client with keepalive must eventually declare the peer dead.
const SilentServer = struct {
    io: Io,
    srv: *net.Server,
    stop: std.atomic.Value(bool) = .init(false),

    fn run(self: *SilentServer) void {
        var stream = self.srv.accept(self.io) catch return;
        defer stream.close(self.io);
        var rbuf: [4096]u8 = undefined;
        var sr = stream.reader(self.io, &rbuf);
        while (!self.stop.load(.acquire)) {
            var tmp: [1024]u8 = undefined;
            _ = sr.interface.readSliceShort(&tmp) catch return;
        }
    }
};

const OpenCtx = struct {
    client: *Client,
    ok: bool = false,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
};
fn openThread(ctx: *OpenCtx) void {
    if (ctx.client.openStream(.{ .path = "/2" }, true)) |_| {
        ctx.ok = true;
    } else |e| {
        ctx.err = e;
    }
    ctx.done.store(true, .release);
}

const ReaderCtx = struct {
    s: *Stream,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
};
fn blockedReader(ctx: *ReaderCtx) void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    if (ctx.s.readEvent(arena.allocator())) |_| {} else |e| {
        ctx.err = e;
    }
    ctx.done.store(true, .release);
}

const SenderCtx = struct {
    s: *Stream,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
};
fn blockedSender(ctx: *SenderCtx) void {
    const payload = @as([200]u8, @splat('x'));
    if (ctx.s.send(&payload, false)) |_| {} else |e| {
        ctx.err = e;
    }
    ctx.done.store(true, .release);
}

const CtFrame = struct {
    hdr: p2.ParsedHeader,
    payload: []u8,
    fn deinit(self: *CtFrame, a: std.mem.Allocator) void {
        a.free(self.payload);
    }
};
fn ctRead(a: std.mem.Allocator, r: *Io.Reader) !CtFrame {
    var hb: [9]u8 = undefined;
    try r.readSliceAll(&hb);
    const hdr = p2.parseHeader(&hb);
    const payload = try a.alloc(u8, hdr.length);
    errdefer a.free(payload);
    if (payload.len > 0) try r.readSliceAll(payload);
    return .{ .hdr = hdr, .payload = payload };
}
/// Reads frames until a GOAWAY, returns its error code (payload[4..8]).
fn ctReadGoawayCode(a: std.mem.Allocator, r: *Io.Reader) !u32 {
    while (true) {
        var f = try ctRead(a, r);
        defer f.deinit(a);
        if (f.hdr.ftype == .goaway) return std.mem.readInt(u32, f.payload[0..][4..8], .big);
    }
}
fn ctWrite(w: *Io.Writer, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
    var hb: [9]u8 = undefined;
    p2.putHeader(&hb, payload.len, ftype, flags, sid);
    try w.writeAll(&hb);
    if (payload.len > 0) try w.writeAll(payload);
    try w.flush();
}
/// Writes only a 9-byte frame header declaring `length` (no payload) — used to
/// trigger the client's size check before it allocates/reads the body.
fn ctWriteHeaderOnly(w: *Io.Writer, ftype: p2.FrameType, sid: u31, length: usize) !void {
    var hb: [9]u8 = undefined;
    p2.putHeader(&hb, length, ftype, 0, sid);
    try w.writeAll(&hb);
    try w.flush();
}
// Common setup: loopback client + raw "server" side; consumes the client's
// preface+SETTINGS and sends SETTINGS+ack. Returns nothing; caller uses the
// captured streams. (Kept inline in each test for clarity — see below.)

test "deinit waits for an in-flight readEvent before freeing the stream (no UAF)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    // A receive thread blocks in readEvent (the peer sends no stream frames).
    const s = try client.openStream(.{ .path = "/x" }, true);
    var ctx = ReaderCtx{ .s = s };
    const rt = try std.Thread.spawn(.{}, blockedReader, .{&ctx});
    // Let it get inside readEvent (past beginOp) and block on recv_cond.
    Io.sleep(io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .awake) catch {};

    // deinit must wake the blocked reader and wait for it to return before
    // freeing `s`; otherwise the reader touches freed memory. Driven inline
    // (not deferred) so we can join the reader after it returns.
    client.deinit();
    rt.join();

    try testing.expect(ctx.done.load(.acquire));
    try testing.expectEqual(error.ConnectionClosed, ctx.err.?);
}

test "a blocked send() is released with error when the stream is reset" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    // Advertise SETTINGS_INITIAL_WINDOW_SIZE=0, then wait for the client's ack
    // so we know it is applied before we open a stream — the stream is then
    // born with a 0 send window and any send() blocks immediately.
    var iw0: [6]u8 = undefined;
    p2.putSetting(&iw0, p2.set_initial_window_size, 0);
    try ctWrite(&asw.interface, .settings, 0, 0, &iw0);
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    const s = try client.openStream(.{ .path = "/x" }, false);

    // A send now blocks on the empty window. Reset the stream; the sender must
    // be released with an error rather than deadlocking forever.
    var ctx = SenderCtx{ .s = s };
    const sender = try std.Thread.spawn(.{}, blockedSender, .{&ctx});
    var rst: [4]u8 = undefined;
    std.mem.writeInt(u32, &rst, @intFromEnum(p2.ErrorCode.cancel), .big);
    ctWrite(&asw.interface, .rst_stream, 0, 1, &rst) catch {};

    var signaled = false;
    var waited: u64 = 0;
    while (waited < 2000) : (waited += 20) {
        if (ctx.done.load(.acquire)) {
            signaled = true;
            break;
        }
        Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    }

    // Cleanup: deinit releases the sender if the reset did not (and, via op
    // draining, only frees the stream once the sender has left send()).
    client.deinit();
    sender.join();

    try testing.expect(signaled); // fails (deadlock) before the fix
    try testing.expectEqual(error.StreamReset, ctx.err.?);
}

test "cancel() wakes a blocked readEvent locally with error.StreamCancelled" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    // A receive thread blocks in readEvent (the peer sends no stream frames).
    const s = try client.openStream(.{ .path = "/x" }, true);
    var ctx = ReaderCtx{ .s = s };
    const rt = try std.Thread.spawn(.{}, blockedReader, .{&ctx});
    Io.sleep(io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .awake) catch {};

    // A cancel() from this thread must wake the blocked reader promptly —
    // sending RST to the peer alone does not (the peer just stops sending).
    try s.cancel();
    var woke = false;
    var waited: u64 = 0;
    while (waited < 2000) : (waited += 20) {
        if (ctx.done.load(.acquire)) {
            woke = true;
            break;
        }
        Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    }

    // Cleanup inline: if cancel() failed to wake the reader, deinit does (with
    // error.ConnectionClosed), so join never hangs — the assertion below is
    // what reports the failure.
    client.deinit();
    rt.join();

    try testing.expect(woke); // false before the fix (reader stays blocked)
    try testing.expectEqual(error.StreamCancelled, ctx.err.?);
}

test "cancel() releases a blocked send() with error.StreamReset" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    // Advertise a zero initial send window and wait for the ack, so the stream
    // is born unable to send and the sender blocks immediately.
    var iw0: [6]u8 = undefined;
    p2.putSetting(&iw0, p2.set_initial_window_size, 0);
    try ctWrite(&asw.interface, .settings, 0, 0, &iw0);
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    const s = try client.openStream(.{ .path = "/x" }, false);
    var ctx = SenderCtx{ .s = s };
    const sender = try std.Thread.spawn(.{}, blockedSender, .{&ctx});
    Io.sleep(io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .awake) catch {};

    // A local cancel() from this thread must release the blocked sender —
    // not just notify the peer.
    try s.cancel();
    var released = false;
    var waited: u64 = 0;
    while (waited < 2000) : (waited += 20) {
        if (ctx.done.load(.acquire)) {
            released = true;
            break;
        }
        Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    }

    client.deinit();
    sender.join();

    try testing.expect(released); // false before the fix (sender stays blocked)
    try testing.expectEqual(error.StreamReset, ctx.err.?);
}

test "client defers WINDOW_UPDATE until DATA is consumed (backpressure)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    // RFC floor, so the handshake emits no stream-0 WINDOW_UPDATE to confuse
    // the "no WINDOW_UPDATE before consumption" assertion below.
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = @intCast(p2.default_window),
    });
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    const s = try client.openStream(.{ .path = "/x" }, true);

    // Response: HEADERS(:status 200), a DATA frame, then a PING. The client
    // processes frames in order, so any WINDOW_UPDATE it emits for the DATA
    // arrives before the PING ack.
    var henc = std.heap.ArenaAllocator.init(testing.allocator);
    defer henc.deinit();
    var blk: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(henc.allocator(), &blk, 200, &.{});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, blk.items);
    try ctWrite(&asw.interface, .data, 0, 1, "hello");
    const ping = @as([8]u8, @splat(0));
    try ctWrite(&asw.interface, .ping, 0, 0, &ping);

    // Drain client output up to the PING ack; no WINDOW_UPDATE may appear yet,
    // because we have not consumed the DATA.
    var saw_wu_before_consume = false;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_wu = f.hdr.ftype == .window_update;
        const is_ping_ack = f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_wu) saw_wu_before_consume = true;
        if (is_ping_ack) break;
    }
    try testing.expect(!saw_wu_before_consume); // fails before the fix

    // Consume the DATA; now the client must credit both windows by 5 bytes.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e1 = try s.readEvent(arena.allocator());
    try testing.expect(e1 == .headers);
    const e2 = try s.readEvent(arena.allocator());
    try testing.expectEqualStrings("hello", e2.data.payload);

    var saw_conn_wu = false;
    var saw_stream_wu = false;
    while (!(saw_conn_wu and saw_stream_wu)) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update) {
            const incr = std.mem.readInt(u32, f.payload[0..4], .big);
            try testing.expectEqual(@as(u32, 5), incr);
            if (f.hdr.sid == 0) saw_conn_wu = true else if (f.hdr.sid == 1) saw_stream_wu = true;
        }
    }
}

test "openStream blocks at MAX_CONCURRENT_STREAMS until a slot frees" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    // Advertise MAX_CONCURRENT_STREAMS = 1, then wait for the client's ack so
    // it is applied before we open streams.
    var mcs: [6]u8 = undefined;
    p2.putSetting(&mcs, p2.set_max_concurrent_streams, 1);
    try ctWrite(&asw.interface, .settings, 0, 0, &mcs);
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    const s1 = try client.openStream(.{ .path = "/1" }, true); // fills the one slot

    // A second open must block on admission.
    var ctx = OpenCtx{ .client = &client };
    const opener = try std.Thread.spawn(.{}, openThread, .{&ctx});

    var waited: u64 = 0;
    while (waited < 500) : (waited += 20) {
        Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    }
    try testing.expect(!ctx.done.load(.acquire)); // still blocked (fails before the feature)

    // Free the slot: end s1 with a Trailers-Only (END_STREAM) response. Slot is
    // released on arrival, not on consume, so s2 can now be admitted.
    var henc = std.heap.ArenaAllocator.init(testing.allocator);
    defer henc.deinit();
    var blk: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(henc.allocator(), &blk, 200, &.{});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 1, blk.items);

    var signaled = false;
    waited = 0;
    while (waited < 2000) : (waited += 20) {
        if (ctx.done.load(.acquire)) {
            signaled = true;
            break;
        }
        Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    }
    opener.join();
    try testing.expect(signaled);
    try testing.expect(ctx.ok);
    _ = s1;
}

test "graceful GOAWAY: streams <= last_id survive, higher ones are refused" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    const s1 = try client.openStream(.{ .path = "/a" }, true); // sid 1
    const s3 = try client.openStream(.{ .path = "/b" }, true); // sid 3

    // GOAWAY(last_stream_id = 1, NO_ERROR), then s1's response.
    var ga: [8]u8 = undefined;
    std.mem.writeInt(u32, ga[0..4], 1, .big);
    std.mem.writeInt(u32, ga[4..8], @intFromEnum(p2.ErrorCode.no_error), .big);
    try ctWrite(&asw.interface, .goaway, 0, 0, &ga);
    var henc = std.heap.ArenaAllocator.init(testing.allocator);
    defer henc.deinit();
    var blk: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(henc.allocator(), &blk, 200, &.{});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 1, blk.items);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // s3 (> last_id) is refused: one .goaway event, then the stream ends.
    const e = try s3.readEvent(arena.allocator());
    try testing.expect(e == .goaway);
    try testing.expectError(error.EndOfStream, s3.readEvent(arena.allocator()));

    // No new streams may be opened after a GOAWAY.
    try testing.expectError(error.GoingAway, client.openStream(.{ .path = "/c" }, true));
    const ga_state = client.goAway().?;
    try testing.expectEqual(@as(u31, 1), ga_state.last_stream_id);

    // s1 (<= last_id) still receives its response — not aborted by the GOAWAY.
    const e1 = try s1.readEvent(arena.allocator());
    try testing.expect(e1 == .headers);
    try testing.expect(e1.headers.end_stream);
}

test "readEvent surfaces a reset once, then ends the stream" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    const s = try client.openStream(.{ .path = "/x" }, true);
    var rst: [4]u8 = undefined;
    std.mem.writeInt(u32, &rst, @intFromEnum(p2.ErrorCode.cancel), .big);
    try ctWrite(&asw.interface, .rst_stream, 0, 1, &rst);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e1 = try s.readEvent(arena.allocator());
    try testing.expect(e1 == .rst);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.cancel)), e1.rst.code);
    // Second call must terminate the drain loop, not block forever.
    try testing.expectError(error.EndOfStream, s.readEvent(arena.allocator()));
}

test "client strips padding from a PADDED DATA frame" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    const s = try client.openStream(.{ .path = "/x" }, true);

    // Response: HEADERS(:status 200), then a PADDED DATA frame carrying "hello"
    // plus a 1-byte pad-length octet (3) and 3 pad bytes.
    var henc = std.heap.ArenaAllocator.init(testing.allocator);
    defer henc.deinit();
    var blk: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(henc.allocator(), &blk, 200, &.{});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, blk.items);
    const padded = [_]u8{3} ++ "hello".* ++ [_]u8{ 0, 0, 0 };
    try ctWrite(&asw.interface, .data, p2.flag_padded | p2.flag_end_stream, 1, &padded);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e1 = try s.readEvent(arena.allocator());
    try testing.expect(e1 == .headers);
    const e2 = try s.readEvent(arena.allocator());
    try testing.expect(e2 == .data);
    try testing.expectEqualStrings("hello", e2.data.payload);
    try testing.expect(e2.data.end_stream);
}

test "client rejects an oversized inbound frame with GOAWAY(FRAME_SIZE_ERROR)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [20000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface); // client SETTINGS
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    const s = try client.openStream(.{ .path = "/x" }, false);
    // A DATA frame declaring length 20000 (> 16384). Header only; the client
    // must reject on the header, before allocating/reading the body.
    try ctWriteHeaderOnly(&asw.interface, .data, 1, 20000);

    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.frame_size_error)), code);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.ConnectionClosed, s.readEvent(arena.allocator()));
}

test "client rejects a CONTINUATION flood with GOAWAY(ENHANCE_YOUR_CALM)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [20000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    // HEADERS (sid 1, END_HEADERS clear) + CONTINUATION frames of 16384 filler
    // bytes each until the accumulated block crosses 256 KiB. 100 + 16*16384 =
    // 262244 > 262144, so the 16th CONTINUATION trips the cap. Content is never
    // decoded (we hit the cap first), so filler is fine.
    var filler: [16384]u8 = @splat('x');
    try ctWrite(&asw.interface, .headers, 0, 1, filler[0..100]);
    var i: usize = 0;
    while (i < 16) : (i += 1) try ctWrite(&asw.interface, .continuation, 0, 1, &filler);

    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.enhance_your_calm)), code);
}

test "client rejects an oversized CONTINUATION with GOAWAY(FRAME_SIZE_ERROR)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    var filler: [100]u8 = @splat('x');
    try ctWrite(&asw.interface, .headers, 0, 1, &filler); // no END_HEADERS
    // A CONTINUATION declaring length 20000 (> 16384). Header only.
    try ctWriteHeaderOnly(&asw.interface, .continuation, 1, 20000);

    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.frame_size_error)), code);
}

test "client advertises SETTINGS_ENABLE_PUSH=0 in its initial SETTINGS" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;

    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    // Read what the client emitted: the connection preface, then its SETTINGS.
    var arbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    try testing.expectEqualSlices(u8, p2.preface, &pf);

    var hb: [9]u8 = undefined;
    try asr.interface.readSliceAll(&hb);
    const fh = p2.parseHeader(&hb);
    try testing.expectEqual(p2.FrameType.settings, fh.ftype);
    const payload = try testing.allocator.alloc(u8, fh.length);
    defer testing.allocator.free(payload);
    try asr.interface.readSliceAll(payload);

    var found_push_disabled = false;
    var i: usize = 0;
    while (i + 6 <= payload.len) : (i += 6) {
        const id = std.mem.readInt(u16, payload[i..][0..2], .big);
        const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
        if (id == p2.set_enable_push) {
            try testing.expectEqual(@as(u32, 0), val);
            found_push_disabled = true;
        }
    }
    try testing.expect(found_push_disabled);
}

test "keepalive declares a silent peer dead instead of hanging" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;

    var silent: SilentServer = .{ .io = io, .srv = &srv };
    const th = try std.Thread.spawn(.{}, SilentServer.run, .{&silent});
    defer th.join();
    defer silent.stop.store(true, .release);

    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const stream = try caddr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var client: Client = undefined;
    try client.init(io, testing.allocator, &sr.interface, &sw.interface);
    defer client.deinit();
    client.keepalive_time_ms = 100;
    client.keepalive_timeout_ms = 100;
    const s = try client.openStream(.{ .path = "/svc/M" }, false);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const start = Io.Timestamp.now(io, .awake).nanoseconds;
    // The peer never sends a frame; the reader PINGs, then declares it dead.
    try testing.expectError(error.ConnectionClosed, s.readEvent(arena_state.allocator()));
    const elapsed_ms = @divFloor(Io.Timestamp.now(io, .awake).nanoseconds - start, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 3000);
}

/// Waits (bounded) for the client's reader to declare the connection dead. A
/// regression test that reads straight for the GOAWAY would block forever on
/// the unfixed code, hanging the suite instead of reporting a failure; this
/// gives it a deadline. The GOAWAY is written and flushed before `kill`, so it
/// is already buffered once this returns.
fn waitDead(io: Io, client: *Client, ms: u64) !void {
    var waited: u64 = 0;
    while (waited < ms) : (waited += 20) {
        if (client.dead.load(.acquire)) return;
        Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    }
    return error.ClientStillAlive;
}

test "client rejects a zero-length CONTINUATION flood with GOAWAY(ENHANCE_YOUR_CALM)" {
    // Empty CONTINUATION frames add no bytes, so `max_header_block` never trips
    // on them; without a frame-count cap readContinuations spins forever on a
    // hostile server (CVE-2024-27316 class). The server side has had this cap;
    // the client's mirror of the loop was missing it.
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    // Teardown order matters: `deinit` joins the reader thread, which only
    // leaves its blocking read once the transport closes. Closing the server
    // side first (this defer runs before `deinit`'s) means that on a build
    // without the fix these tests fail on waitDead's deadline instead of
    // hanging the suite in `deinit`.
    defer client.deinit();
    defer accepted.close(io);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [8192]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    // HEADERS (sid 1, END_HEADERS clear), then empty CONTINUATIONs past the cap.
    try ctWrite(&asw.interface, .headers, 0, 1, "");
    var i: usize = 0;
    while (i < 400) : (i += 1) ctWrite(&asw.interface, .continuation, 0, 1, "") catch break;

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.enhance_your_calm)), code);
}

test "client treats a stray CONTINUATION as a connection PROTOCOL_ERROR" {
    // A CONTINUATION with no HEADERS to continue was ignored, dropping a header
    // block fragment and desyncing HPACK for every later frame.
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    // Teardown order matters: `deinit` joins the reader thread, which only
    // leaves its blocking read once the transport closes. Closing the server
    // side first (this defer runs before `deinit`'s) means that on a build
    // without the fix these tests fail on waitDead's deadline instead of
    // hanging the suite in `deinit`.
    defer client.deinit();
    defer accepted.close(io);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");

    try ctWrite(&asw.interface, .continuation, p2.flag_end_headers, 1, "");

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.protocol_error)), code);
}

test "client treats a HEADERS whose padding exceeds the payload as a connection PROTOCOL_ERROR" {
    // Symmetric with the server's "padding exceeds payload" test. Trimming a bad
    // prefix and decoding the remainder anyway desyncs HPACK for the rest of the
    // connection, silently — the same class this PR closed on the server.
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();
    defer accepted.close(io);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");

    const s = try client.openStream(.{ .path = "/x" }, true);
    _ = s;
    // PADDED response HEADERS declaring 200 bytes of padding over a 1-byte
    // fragment. The fragment alone (0x88 = indexed ":status 200") is a complete,
    // valid block, so on the old silent-trim path the client decodes it happily
    // and stays alive — the test then fails on waitDead's deadline rather than
    // passing for the wrong reason or blocking on a GOAWAY that never comes.
    const padded = [_]u8{ 200, 0x88 };
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_padded, 1, &padded);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.protocol_error)), code);
}

test "openStream seeds a new stream's window from the peer's INITIAL_WINDOW_SIZE" {
    // Pins the seeding itself: a stream opened after the peer's SETTINGS must
    // start at the advertised window, not the RFC default. (The lock that makes
    // the seed atomic against a concurrent applyInitialWindow is not directly
    // observable — breaking the atomicity is what a race test would require.)
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();
    defer accepted.close(io);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);

    // Advertise a non-default initial window, then wait for our ack so the
    // setting is known to be applied before the stream is opened.
    var iw: [6]u8 = undefined;
    p2.putSetting(&iw, p2.set_initial_window_size, 4096);
    try ctWrite(&asw.interface, .settings, 0, 0, &iw);
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    const s = try client.openStream(.{ .path = "/x" }, false);
    client.send_mu.lockUncancelable(io);
    const window = s.send_window;
    client.send_mu.unlock(io);
    try testing.expectEqual(@as(i64, 4096), window);
}

// --- framing-validation regression tests (#8): the reader now applies the
// same RFC 7540 §4/§6 rules the server does, via proto.validateInboundFrame. ---

fn ctHandshake(asr: *Io.Reader, asw: *Io.Writer) !void {
    var pf: [p2.preface.len]u8 = undefined;
    try asr.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, asr); // client SETTINGS
    cs.deinit(testing.allocator);
    try ctWrite(asw, .settings, 0, 0, "");
    try ctWrite(asw, .settings, p2.flag_ack, 0, "");
}

test "client GOAWAYs a SETTINGS frame on a nonzero stream" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    // SETTINGS must arrive on stream 0 (RFC 7540 §6.5).
    try ctWrite(&asw.interface, .settings, 0, 1, "");

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.protocol_error)), code);
    client.deinit();
}

test "client GOAWAYs a SETTINGS ack carrying a payload" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    var s: [6]u8 = undefined;
    p2.putSetting(&s, p2.set_initial_window_size, 1);
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, &s);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.frame_size_error)), code);
    client.deinit();
}

test "client GOAWAYs a PING with a bad length" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    // PING must be exactly 8 bytes (RFC 7540 §6.7).
    try ctWrite(&asw.interface, .ping, 0, 0, "123456789");

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.frame_size_error)), code);
    client.deinit();
}

test "client GOAWAYs a WINDOW_UPDATE with a bad length" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    // WINDOW_UPDATE must be exactly 4 bytes (RFC 7540 §6.9).
    try ctWrite(&asw.interface, .window_update, 0, 0, "abc");

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.frame_size_error)), code);
    client.deinit();
}

test "client GOAWAYs a peer MAX_FRAME_SIZE outside the RFC range" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    // Below the 2^14 floor (RFC 7540 §6.5.2). The value was previously
    // ignored, leaving the connection running against an illegal setting.
    var s: [6]u8 = undefined;
    p2.putSetting(&s, p2.set_max_frame_size, 16383);
    try ctWrite(&asw.interface, .settings, 0, 0, &s);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.protocol_error)), code);
    client.deinit();
}

test "client resets a stream WINDOW_UPDATE with a zero increment" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    _ = try client.openStream(.{ .path = "/x" }, false);
    // A 0 increment on a stream is a stream PROTOCOL_ERROR (RFC 7540 §6.9):
    // RST the stream, keep the connection.
    try ctWrite(&asw.interface, .window_update, 0, 1, &[_]u8{ 0, 0, 0, 0 });

    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .rst_stream) {
            try testing.expectEqual(@as(u31, 1), f.hdr.sid);
            try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.protocol_error)), std.mem.readInt(u32, f.payload[0..4], .big));
            break;
        }
    }
    // The connection must survive a stream-level framing mistake.
    Io.sleep(io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(!client.dead.load(.acquire));
}

test "client GOAWAYs FLOW_CONTROL_ERROR when INITIAL_WINDOW_SIZE overflows a stream window" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    const s = try client.openStream(.{ .path = "/x" }, false);
    // Raise stream 1's send window to exactly 2^31-1 ...
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, 0x7fff_ffff - 65535, .big);
    try ctWrite(&asw.interface, .window_update, 0, 1, &wu);
    // ... then raise the initial window by one: the delta shifts every open
    // stream past the 2^31-1 ceiling (RFC 7540 §6.9.2).
    var st: [6]u8 = undefined;
    p2.putSetting(&st, p2.set_initial_window_size, 65536);
    try ctWrite(&asw.interface, .settings, 0, 0, &st);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.flow_control_error)), code);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.ConnectionClosed, s.readEvent(arena_state.allocator()));
    client.deinit();
}

// --- inbound flow-control regression tests (#3) ---

test "client GOAWAYs DATA beyond the connection receive window" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    // Pinned to the RFC floor: this test is about the overflow check, not about
    // what the default window happens to be.
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = @intCast(p2.default_window),
    });

    var arbuf: [8192]u8 = undefined;
    var awbuf: [70000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    _ = try client.openStream(.{ .path = "/x" }, false);
    var big: [16384]u8 = @splat('x');
    // 16384 * 4 = 65536 > the 65535-byte connection window: the fourth frame
    // crosses it. Previously all of it was buffered without bound.
    try ctWrite(&asw.interface, .data, 0, 1, &big);
    try ctWrite(&asw.interface, .data, 0, 1, &big);
    try ctWrite(&asw.interface, .data, 0, 1, &big);
    try ctWrite(&asw.interface, .data, 0, 1, &big);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.flow_control_error)), code);
    client.deinit();
}

test "client keeps receiving after consumed DATA is credited back" {
    // Deduct-on-arrival must pair with credit-on-consumption: after the caller
    // drains three frames and the windows are replenished, a fourth frame is
    // legal again. (Without the ledger growing with the granted credit, the
    // fourth frame would look like an overflow.)
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [8192]u8 = undefined;
    var awbuf: [70000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    const s = try client.openStream(.{ .path = "/x" }, false);
    var chunk: [16384]u8 = @splat('y');
    try ctWrite(&asw.interface, .data, 0, 1, &chunk);
    try ctWrite(&asw.interface, .data, 0, 1, &chunk);
    try ctWrite(&asw.interface, .data, 0, 1, &chunk);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const ev = try s.readEvent(arena);
        try testing.expectEqual(@as(usize, 16384), ev.data.payload.len);
    }

    // The three stream-level WINDOW_UPDATEs only flow once the caller consumed
    // the frames; the peer waits for them, so this frame is legal.
    var seen_wu: u32 = 0;
    while (seen_wu < 3) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update and f.hdr.sid == 1) seen_wu += 1;
    }
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, 1, &chunk);

    const ev4 = try s.readEvent(arena);
    try testing.expectEqual(@as(usize, 16384), ev4.data.payload.len);
    try testing.expect(ev4.data.end_stream);
    try testing.expectError(error.EndOfStream, s.readEvent(arena));
    try testing.expect(!client.dead.load(.acquire));
}

// --- outbound header-block splitting regression tests (#4) ---

test "openStream splits a large header block into HEADERS + CONTINUATION" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [25000]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface); // client SETTINGS
    cs.deinit(testing.allocator);

    // The block encodes well past the peer's 16384-byte max frame size: one
    // HEADERS frame used to carry it all (a FRAME_SIZE_ERROR to the peer).
    // 0xff bytes have no huffman compression (8 code bits each), so the value
    // survives encoding at ~full length.
    var big: [20000]u8 = @splat(0xff);
    _ = try client.openStream(.{ .path = "/big", .headers = &.{.{ .name = "x-big", .value = &big }} }, true);

    // Skip the client's SETTINGS ack, then expect HEADERS (exactly max frame
    // size, END_STREAM set, END_HEADERS clear) followed by CONTINUATION(s).
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var block: std.ArrayList(u8) = .empty;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype != .headers) continue; // settings ack
        try testing.expectEqual(@as(u31, 1), f.hdr.sid);
        try testing.expectEqual(@as(u32, 16384), f.hdr.length);
        try testing.expect(f.hdr.flags & p2.flag_end_stream != 0);
        try testing.expect(f.hdr.flags & p2.flag_end_headers == 0);
        try block.appendSlice(arena, f.payload);
        break;
    }
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.continuation, f.hdr.ftype);
        try testing.expectEqual(@as(u31, 1), f.hdr.sid);
        try testing.expect(f.hdr.length <= 16384);
        try block.appendSlice(arena, f.payload);
        if (f.hdr.flags & p2.flag_end_headers != 0) break;
    }

    var dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size);
    defer dec.deinit();
    const hs = try dec.decode(arena, block.items);
    var found = false;
    for (hs) |h| {
        if (std.mem.eql(u8, h.name, "x-big")) {
            found = true;
            try testing.expectEqual(@as(usize, 20000), h.value.len);
        }
    }
    try testing.expect(found);
}

test "openStream rejects a header block above the cap" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    // ~500KB of incompressible value bytes: past the 256KiB cap, rejected
    // before any oversized frame reaches the wire (or overflows putHeader's
    // 24-bit length field).
    const too_big = try testing.allocator.alloc(u8, 500000);
    defer testing.allocator.free(too_big);
    @memset(too_big, 0xff);
    try testing.expectError(
        error.HeadersTooLarge,
        client.openStream(.{ .path = "/huge", .headers = &.{.{ .name = "x-big", .value = too_big }} }, false),
    );
}

test "client GOAWAYs DATA on an idle stream id" {
    // DATA on an id at or above the highest we ever allocated is a connection
    // PROTOCOL_ERROR (RFC 9113 §5.1) — the same rule the server enforces.
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    // No stream was ever opened (next_id == 1): sid 1 is idle.
    try ctWrite(&asw.interface, .data, 0, 1, "xxxx");

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.protocol_error)), code);
    client.deinit();
}

test "client RSTs DATA on a closed stream and keeps the connection" {
    // An id below the highest allocated that is no longer open was closed:
    // a stream error — RST(STREAM_CLOSED) — with the connection window still
    // returned (RFC 9113 §5.1, RFC 7540 §6.9).
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    const s = try client.openStream(.{ .path = "/x" }, false);
    s.close(); // sends RST(CANCEL), deregisters the stream; next_id is now 3

    try ctWrite(&asw.interface, .data, 0, 1, "xxxx");
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .rst_stream and f.hdr.sid == 1 and
            std.mem.readInt(u32, f.payload[0..4], .big) == @intFromEnum(p2.ErrorCode.stream_closed))
        {
            break;
        }
    }
    // A stream-level mistake must not take the connection down.
    Io.sleep(io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(!client.dead.load(.acquire));
}

test "client GOAWAYs a peer PUSH_PROMISE before tearing down" {
    // We advertised ENABLE_PUSH=0: a push is a PROTOCOL_ERROR (RFC 9113 §6.6),
    // and its header block must not be dropped silently (HPACK desync).
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);

    var pp: [5]u8 = undefined;
    std.mem.writeInt(u32, pp[0..4], 2, .big); // promised stream 2
    pp[4] = 0x88;
    try ctWrite(&asw.interface, .push_promise, p2.flag_end_headers, 0, &pp);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @intFromEnum(p2.ErrorCode.protocol_error)), code);
    client.deinit();
}

test "the client advertises its receive windows during the handshake" {
    // Both halves of the window it is prepared to receive into: the per-stream
    // one via SETTINGS_INITIAL_WINDOW_SIZE, and the connection one via a
    // stream-0 WINDOW_UPDATE — SETTINGS cannot carry the latter, which is
    // fixed at 65535 and only ever grows by WINDOW_UPDATE (RFC 7540 §6.9.2).
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = 1 << 20,
        .initial_window_size = 512 * 1024,
    });
    defer client.deinit();
    defer accepted.close(io);

    var arbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);

    var settings = try ctRead(testing.allocator, &asr.interface);
    defer settings.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.settings, settings.hdr.ftype);
    var advertised_iw: ?u32 = null;
    var i: usize = 0;
    while (i + 6 <= settings.payload.len) : (i += 6) {
        const id = std.mem.readInt(u16, settings.payload[i..][0..2], .big);
        const val = std.mem.readInt(u32, settings.payload[i + 2 ..][0..4], .big);
        if (id == p2.set_initial_window_size) advertised_iw = val;
    }
    try testing.expectEqual(@as(u32, 512 * 1024), advertised_iw.?);

    // Send our SETTINGS so the client owes us an ack, then read until it
    // arrives, noting any stream-0 WINDOW_UPDATE on the way. Reading straight
    // for the WINDOW_UPDATE would block forever on a build that never sends
    // one — a hang instead of a failure.
    var awbuf2: [256]u8 = undefined;
    var asw2 = accepted.writer(io, &awbuf2);
    try ctWrite(&asw2.interface, .settings, 0, 0, "");
    var conn_incr: ?u32 = null;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update and f.hdr.sid == 0) {
            conn_incr = std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
        }
        if (f.hdr.ftype == .settings and f.hdr.flags & p2.flag_ack != 0) break;
    }
    try testing.expectEqual(@as(u32, (1 << 20) - 65535), conn_incr.?);
}

test "a default client keeps the RFC floor untouched when configured to it" {
    // The floor is a legal configuration and must emit no stream-0
    // WINDOW_UPDATE at all — enlarging by zero would be a PROTOCOL_ERROR.
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = @intCast(p2.default_window),
    });
    defer client.deinit();
    defer accepted.close(io);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var settings = try ctRead(testing.allocator, &asr.interface);
    settings.deinit(testing.allocator);

    // Next frame from the client must be its SETTINGS ack for ours, not a
    // WINDOW_UPDATE.
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    var next = try ctRead(testing.allocator, &asr.interface);
    defer next.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.settings, next.hdr.ftype);
    try testing.expect(next.hdr.flags & p2.flag_ack != 0);
}

test "an enlarged connection window accepts more than 65535 bytes in flight" {
    // The point of the knob: with the RFC floor a peer may only have 65535
    // bytes outstanding before it must wait for a WINDOW_UPDATE, which caps a
    // download at roughly one window per round trip. Here the peer pushes
    // ~96 KiB without waiting for anything, and the client must take it
    // instead of answering FLOW_CONTROL_ERROR.
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    defer cstream.close(io);
    var accepted = try srv.accept(io);

    var crbuf: [8192]u8 = undefined;
    var cwbuf: [8192]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = 1 << 20,
        .initial_window_size = 1 << 20,
    });
    defer client.deinit();
    defer accepted.close(io);

    var arbuf: [8192]u8 = undefined;
    var awbuf: [65536]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    // Drain the handshake up to our ack rather than assuming the next frame is
    // the stream-0 enlargement, so a build that omits it fails on the transfer
    // below instead of blocking here.
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .settings and f.hdr.flags & p2.flag_ack != 0) break;
    }

    const s = try client.openStream(.{ .path = "/big" }, true);
    var hf = try ctRead(testing.allocator, &asr.interface);
    while (hf.hdr.ftype != .headers) {
        hf.deinit(testing.allocator);
        hf = try ctRead(testing.allocator, &asr.interface);
    }
    const sid = hf.hdr.sid;
    hf.deinit(testing.allocator);

    var blk: struct { buf: std.ArrayList(u8) = .empty } = .{};
    defer blk.buf.deinit(testing.allocator);
    try blk.buf.append(testing.allocator, 0x88); // :status 200
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, sid, blk.buf.items);

    // 6 x 16 KiB = 98304 bytes, all before the client has consumed anything.
    var chunk: [16384]u8 = @splat('z');
    var sent: usize = 0;
    while (sent < 6) : (sent += 1) try ctWrite(&asw.interface, .data, 0, sid, &chunk);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, sid, "");

    // Let the client's reader take all of it in BEFORE we consume anything.
    // That is the state under test: the peer has ~96 KiB outstanding while we
    // are still busy. Without the pause the consumer below races the reader,
    // replenishing as it goes, and a 65535-byte window might never be
    // exceeded — the test would pass on an unfixed build depending on timing.
    std.Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .awake) catch {};

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var got: usize = 0;
    while (true) {
        const ev = try s.readEvent(arena_state.allocator());
        switch (ev) {
            .data => |d| {
                got += d.payload.len;
                if (d.end_stream) break;
            },
            .headers => |h| if (h.end_stream) break,
            .rst, .goaway => return error.UnexpectedStreamEnd,
        }
        _ = arena_state.reset(.retain_capacity);
    }
    try testing.expectEqual(@as(usize, 6 * 16384), got);
}
