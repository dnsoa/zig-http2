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
//!   defer s.close();
//!   try s.send("ping", true);
//!   switch (try s.readEvent(arena)) { .headers => ..., .data => ..., ... }
//!   ```
//! `deinit` stops the reader (cancelling any in-flight read on concurrent
//! `std.Io` backends; close the transport as well for non-concurrent fallback
//! and prompt peer teardown). Keepalive (optional) detects half-open peers.

const std = @import("std");
const Io = std.Io;
const types = @import("types.zig");
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

/// One inbound item buffered on a stream's queue. Response DATA bytes are
/// stored in the stream's contiguous circular `rx_buf` (`proto.RxRing`) rather
/// than individual `gpa`-allocated slices; `Queued.data` tracks only the
/// unpadded byte length (`len`) and wire flow-control cost (`fc_cost`).
const Queued = union(enum) {
    headers: []const Header,
    data: struct { len: u32, fc_cost: u32 },
};

/// Hard cap on one response's accumulated header block across HEADERS +
/// CONTINUATION (CVE-2024-27316 class); matches the server's bound.
const max_header_block: usize = 256 * 1024;
/// Cap on CONTINUATION frames per header block, mirroring the server's. Bytes
/// are already bounded by `max_header_block`, but a zero-length CONTINUATION
/// adds none, so a peer streaming empty ones makes no byte progress and the
/// size cap never fires — `readContinuations` would loop forever. A legitimate
/// block needs a handful (256KiB / 16KiB ⇒ ~16), so this is generous.
const max_continuation_frames: usize = 256;
/// Max DATA payload bytes coalesced into one `write_mu` acquisition + `w.flush()`
/// batch (4 default 16 KiB frames). Keeps typical unary/POST payloads in 1 flush
/// while bounding `write_mu` hold time so control frames and concurrent streams
/// stay responsive during large uploads (#44).
const max_write_batch: usize = 64 * 1024;

/// Tunables for a client connection. `Client.init` uses these defaults; pass
/// custom values via `Client.initWithConfig`.
pub const Config = struct {
    /// Connection-level inbound flow-control window, aggregated across streams.
    /// RFC 9113 fixes the initial connection window at 65535; anything larger is
    /// advertised via a stream-0 WINDOW_UPDATE during handshake. Clamped to
    /// [65535, 2^31-1]. Default 1 MiB matches the server (#39).
    connection_window_size: u32 = 1 << 20,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` advertised for each stream we open.
    /// Clamped to [0, 2^31-1]. Default 1 MiB (#39).
    initial_window_size: u32 = 1 << 20,
    /// `SETTINGS_MAX_FRAME_SIZE` advertised and enforced on inbound frames,
    /// clamped to `[16384, 16777215]`. Larger values reduce framing overhead
    /// on high-throughput origin fetches.
    max_frame_size: u32 = p2.our_max_frame_size,
    /// Bound on flushing outbound frame batches to the transport (0 = unbounded).
    write_timeout_ms: u64 = 30_000,
    /// Optional keepalive PING interval (ms). 0 disables keepalive.
    keepalive_time_ms: u64 = 0,
    /// Keepalive PING response / mid-frame stall timeout (ms). When 0 and
    /// `keepalive_time_ms > 0`, falls back to `keepalive_time_ms`.
    keepalive_timeout_ms: u64 = 0,
    /// Force spawning a dedicated OS thread for `readerLoop` instead of
    /// scheduling onto `Io.Group.concurrent` first.
    spawn_reader_thread: bool = false,
    /// Upper bound on our outbound HPACK encoder dynamic table size (bytes),
    /// capping per-connection memory even if the server advertises a massive
    /// `SETTINGS_HEADER_TABLE_SIZE`. Set to 0 to disable dynamic-table encoding.
    max_encoder_table_size: u32 = p2.our_header_table_size,
};

const ClientConfig = Config;

pub const Stream = struct {
    client: *Client,
    id: u31,
    /// Flow-control window for DATA we send, guarded by `client.send_mu`.
    send_window: i64,
    /// Per-stream send wakeup condition (guarded by `client.send_mu`) so
    /// stream-level `WINDOW_UPDATE`/`RST_STREAM`/`cancel` wakes only this stream.
    send_cond: Io.Condition = .init,
    /// True while parked on `client.send_cond` waiting for connection send window.
    /// Guarded by `client.send_mu`.
    waiting_conn_window: bool = false,
    /// Flow-control window for DATA we receive (RFC 7540 §6.9.2), decremented
    /// by the reader thread on each DATA frame and credited back as the caller
    /// consumes items. Guarded by `recv_mu`; written by the reader under
    /// streams_mu -> recv_mu, read/credited by readEvent under recv_mu.
    recv_window: i64 = p2.default_window,
    /// Consumed-but-not-yet-acknowledged stream bytes, flushed as a batched
    /// stream WINDOW_UPDATE once reaching half of `initial_window_size`. recv_mu.
    recv_pending: i64 = 0,

    recv_mu: Io.Mutex = .init,
    recv_cond: Io.Condition = .init,
    rx_buf: p2.RxRing = .{},
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
    /// True once our side has sent END_STREAM (on HEADERS or DATA). Atomic so
    /// `deliver`, `send`, and `close` can inspect local half-close state without
    /// taking `admit_mu` under `recv_mu`.
    local_closed: std.atomic.Value(bool) = .init(false),

    is_head_request: bool = false,
    resp_phase: RespPhase = .expect_headers,
    resp_content_length: ?u64 = null,
    rx_body_bytes: u64 = 0,

    const RespPhase = enum { expect_headers, expect_body_or_trailers };

    fn advanceQueue(self: *Stream) void {
        self.q_head += 1;
        if (self.q_head == self.queue.items.len) {
            // Fully drained: reclaim the backing arrays and reset the cursor.
            self.queue.clearRetainingCapacity();
            self.end_flags.clearRetainingCapacity();
            self.is_headers.clearRetainingCapacity();
            self.q_head = 0;
        }
    }

    /// Updates stream-level pending receive credit while `self.recv_mu` is held.
    fn consumeStreamWindowLocked(self: *Stream, amt: u32) struct { stream_amt: u32, stream_ended: bool } {
        if (amt == 0) return .{ .stream_amt = 0, .stream_ended = true };
        const c = self.client;
        if (!self.remote_closed and self.reset == null and !self.cancelled and !self.goaway_refused) {
            self.recv_pending += @as(i64, amt);
            const iw: i64 = @intCast(p2.clampInitialWindow(c.cfg.initial_window_size));
            const threshold = @max(@as(i64, 1), iw >> 1);
            if (self.recv_pending >= threshold) {
                const room: i64 = 0x7fff_ffff - self.recv_window;
                const grant = @min(self.recv_pending, @max(@as(i64, 0), room));
                if (grant > 0) {
                    self.recv_window += grant;
                    self.recv_pending -= grant;
                    return .{ .stream_amt = @intCast(grant), .stream_ended = false };
                }
            }
            return .{ .stream_amt = 0, .stream_ended = false };
        }
        return .{ .stream_amt = 0, .stream_ended = true };
    }

    /// Sends `data` as flow-controlled DATA frames; `end_stream` half-closes.
    /// Blocks while the send window is empty; errors on reset/teardown.
    pub fn send(self: *Stream, data: []const u8, end_stream: bool) !void {
        const c = self.client;
        if (!c.tryBeginOp()) return error.ConnectionClosed;
        defer c.endOp();
        if (self.local_closed.load(.acquire)) return error.StreamClosed;
        if (data.len == 0) {
            if (end_stream) {
                try c.writeDataForStream(self, "", true);
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
                if (self.local_closed.load(.acquire)) {
                    c.send_mu.unlock(c.io);
                    return error.StreamClosed;
                }
                if (self.send_window <= 0) {
                    self.send_cond.waitUncancelable(c.io, &c.send_mu);
                    continue;
                }
                if (c.conn_send_window <= 0) {
                    self.waiting_conn_window = true;
                    defer self.waiting_conn_window = false;
                    c.send_cond.waitUncancelable(c.io, &c.send_mu);
                    continue;
                }
                const avail = @min(self.send_window, c.conn_send_window);
                const batch_cap: usize = @max(max_write_batch, c.peer_max_frame.load(.acquire));
                const want: i64 = @min(@as(i64, @intCast(data.len - off)), @min(avail, @as(i64, @intCast(batch_cap))));
                self.send_window -= want;
                c.conn_send_window -= want;
                break :blk @as(usize, @intCast(want));
            };
            c.send_mu.unlock(c.io);
            const last = off + n == data.len;
            c.writeDataForStream(self, data[off .. off + n], end_stream and last) catch |err| {
                if (err == error.StreamReset or err == error.StreamClosed) {
                    // Frame was not written on the wire; return both stream and connection send credit.
                    c.send_mu.lockUncancelable(c.io);
                    self.send_window += @as(i64, @intCast(n));
                    c.conn_send_window += @as(i64, @intCast(n));
                    c.send_cond.broadcast(c.io);
                    c.send_mu.unlock(c.io);
                }
                return err;
            };
            off += n;
        }
        if (end_stream) {
            c.noteEnd(self, true, false); // local half-closed
        }
    }

    /// Reads the next event on this stream, blocking until one is available.
    /// Decoded headers / copied DATA are owned by `arena`. Returns
    /// `error.EndOfStream` once the peer has half-closed and the queue drains,
    /// `error.ConnectionClosed` when the connection tears down.
    pub fn readEvent(self: *Stream, arena: std.mem.Allocator) !Event {
        const c = self.client;
        if (!c.tryBeginOp()) return error.ConnectionClosed;
        defer c.endOp();
        // Credit connection + stream flow-control windows after releasing
        // `recv_mu` (defers run LIFO) without re-locking `streams_mu`.
        var credit: u32 = 0;
        var stream_wu: u32 = 0;
        var stream_ended = true;
        defer if (credit > 0) {
            const conn_amt = c.creditConn(credit, stream_ended);
            c.writeWindowUpdates(conn_amt, self.id, stream_wu);
        };
        self.recv_mu.lockUncancelable(c.io);
        defer self.recv_mu.unlock(c.io);
        while (true) {
            // A local cancel() takes priority: return promptly (dropping any
            // buffered items) so a blocked reader wakes the moment another
            // thread cancels the stream.
            if (self.cancelled) return error.StreamCancelled;
            if (self.queue.items.len > self.q_head) {
                const item = self.queue.items[self.q_head];
                const end_stream = self.end_flags.items[self.q_head];
                const is_hdr = self.is_headers.items[self.q_head];
                // Allocate on `arena` BEFORE popping from `self.queue`/`rx_buf`:
                // if `arena` OOMs, the buffered item stays queued so `close`/
                // `deinit` still frees it and returns its flow-control credit.
                if (is_hdr) {
                    const hs = item.headers;
                    const out = try arena.alloc(Header, hs.len);
                    var copied: usize = 0;
                    errdefer {
                        for (out[0..copied]) |h| {
                            hpack.freeSlice(arena, h.name);
                            hpack.freeSlice(arena, h.value);
                        }
                        arena.free(out);
                    }
                    for (hs, 0..) |h, i| {
                        const name = if (hpack.isStaticSlice(h.name)) h.name else try arena.dupe(u8, h.name);
                        errdefer hpack.freeSlice(arena, name);
                        const value = if (hpack.isStaticSlice(h.value)) h.value else try arena.dupe(u8, h.value);
                        out[i] = .{ .name = name, .value = value };
                        copied = i + 1;
                    }
                    self.advanceQueue();
                    freeHeaders(c.gpa, hs);
                    return .{ .headers = .{ .sid = self.id, .headers = out, .end_stream = end_stream } };
                } else {
                    const data_len: usize = item.data.len;
                    const out = try arena.alloc(u8, data_len);
                    const got = self.rx_buf.read(out);
                    std.debug.assert(got == data_len);
                    const fc = item.data.fc_cost;
                    self.advanceQueue();
                    const sw = self.consumeStreamWindowLocked(fc);
                    credit = fc;
                    stream_wu = sw.stream_amt;
                    stream_ended = sw.stream_ended;
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

    /// Streams response body bytes directly into caller-owned `dst` from the
    /// bounded circular `rx_buf` with **zero heap allocations**.
    ///
    /// Typical usage: read initial response `.headers` via `readEvent`, then
    /// loop `readBody(&buf)` until it returns `0` (end of body or start of
    /// trailing `HEADERS`, which remain readable via a subsequent `readEvent`).
    /// Returns `error.HeadersPending` if unconsumed non-`END_STREAM` response
    /// headers are still at the front of the queue.
    pub fn readBody(self: *Stream, dst: []u8) !usize {
        if (dst.len == 0) return 0;
        const c = self.client;
        if (!c.tryBeginOp()) return error.ConnectionClosed;
        defer c.endOp();
        var credit: u32 = 0;
        var stream_wu: u32 = 0;
        var stream_ended = true;
        defer if (credit > 0) {
            const conn_amt = c.creditConn(credit, stream_ended);
            c.writeWindowUpdates(conn_amt, self.id, stream_wu);
        };
        self.recv_mu.lockUncancelable(c.io);
        defer self.recv_mu.unlock(c.io);

        var copied: usize = 0;
        while (true) {
            if (self.cancelled) return error.StreamCancelled;
            var hit_eof = false;
            while (self.queue.items.len > self.q_head) {
                const is_hdr = self.is_headers.items[self.q_head];
                const end_stream = self.end_flags.items[self.q_head];
                if (is_hdr) {
                    if (copied > 0) {
                        const sw = self.consumeStreamWindowLocked(credit);
                        stream_wu = sw.stream_amt;
                        stream_ended = sw.stream_ended;
                        return copied;
                    }
                    if (end_stream) return 0; // Trailers (or Trailers-Only): body is complete.
                    return error.HeadersPending;
                }
                const item = &self.queue.items[self.q_head].data;
                const overhead: u32 = item.fc_cost - item.len;
                if (item.len == 0) {
                    credit += item.fc_cost;
                    self.advanceQueue();
                    if (end_stream) {
                        hit_eof = true;
                        break;
                    }
                    continue;
                }
                if (copied == dst.len) break;
                const want: usize = @min(dst.len - copied, @as(usize, item.len));
                const got = self.rx_buf.read(dst[copied .. copied + want]);
                std.debug.assert(got == want);
                copied += got;
                const got_u32: u32 = @intCast(got);
                const fc_take: u32 = got_u32 + overhead;
                credit += fc_take;
                item.len -= got_u32;
                item.fc_cost -= fc_take;
                if (item.len == 0) {
                    std.debug.assert(item.fc_cost == 0);
                    self.advanceQueue();
                    if (end_stream) {
                        hit_eof = true;
                        break;
                    }
                }
            }
            if (copied > 0) {
                const sw = self.consumeStreamWindowLocked(credit);
                stream_wu = sw.stream_amt;
                stream_ended = sw.stream_ended;
                return copied;
            }
            if (hit_eof) {
                if (credit > 0) {
                    const sw = self.consumeStreamWindowLocked(credit);
                    stream_wu = sw.stream_amt;
                    stream_ended = sw.stream_ended;
                }
                return 0;
            }
            if (self.reset != null) return error.StreamReset;
            if (self.goaway_refused) return error.GoingAway;
            if (c.dead.load(.acquire)) return error.ConnectionClosed;
            if (self.remote_closed) {
                if (credit > 0) {
                    const sw = self.consumeStreamWindowLocked(credit);
                    stream_wu = sw.stream_amt;
                    stream_ended = sw.stream_ended;
                }
                return 0;
            }
            self.recv_cond.waitUncancelable(c.io, &self.recv_mu);
        }
    }

    fn streamBodyReadAdapter(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *Stream = @ptrCast(@alignCast(ctx));
        return self.readBody(buf);
    }

    /// Returns a `types.BodyReader` backed by `readBody` for zero-allocation
    /// streaming origin-to-edge forwarding.
    pub fn bodyReader(self: *Stream) types.BodyReader {
        return .{ .ctx = self, .readFn = streamBodyReadAdapter };
    }

    /// Cancels the stream: wakes any local reader/sender, then sends
    /// RST_STREAM(CANCEL) so the peer tears down its half. Safe to call from
    /// another thread than the one blocked in `readEvent`/`send`. Stop using
    /// the stream afterwards.
    pub fn cancel(self: *Stream) !void {
        const c = self.client;
        if (!c.tryBeginOp()) return error.ConnectionClosed;
        defer c.endOp();
        // Wake local waiters first, so a blocked readEvent/send returns
        // promptly even if writeFrame below blocks or fails.
        self.abortLocal();
        c.noteEnd(self, true, true); // reset closes both directions
        if (c.dead.load(.acquire)) return error.ConnectionClosed;
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, @backingInt(p2.ErrorCode.cancel), .big);
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
        c.wakeStreamSender(self);
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
    /// stream). Do NOT call `close` once `Client.deinit` has begun (`deinit`
    /// reclaims all remaining streams itself); if separate threads hold
    /// `*Stream` handles with `defer s.close()`, cancel the streams and `join`
    /// those threads before calling `deinit`.
    pub fn close(self: *Stream) void {
        const c = self.client;
        if (!c.tryBeginOp()) return; // deinit owns the stream table and frees remaining streams
        defer c.endOp();
        self.recv_mu.lockUncancelable(c.io);
        // Only skip RST_STREAM when the stream is fully closed (both halves
        // ended), already reset/cancelled, or refused by GOAWAY. A stream in
        // half-closed (remote) still has an open send half on the peer and
        // needs RST_STREAM(CANCEL) so the peer does not hang waiting for body.
        const ended = (self.remote_closed and self.local_closed.load(.acquire)) or
            self.reset != null or self.cancelled or self.goaway_refused;
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
    /// were already consumed (and freed) by `readEvent`/`readBody`, so only
    /// `[q_head..]` remains to free alongside `rx_buf`.
    fn freeQueued(self: *Stream, gpa: std.mem.Allocator) void {
        for (self.queue.items[self.q_head..], self.is_headers.items[self.q_head..]) |item, is_hdr| {
            if (is_hdr) freeHeaders(gpa, item.headers);
        }
        self.rx_buf.deinit(gpa);
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

const HtsUpdate = struct { min: u32, last: u32 };
const op_wait_bit: u32 = 1 << 30;
const op_sealed_bit: u32 = 1 << 31;
const op_count_mask: u32 = ~(op_wait_bit | op_sealed_bit);

pub const Client = struct {
    pub const Config = ClientConfig;

    io: Io,
    gpa: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    dec: hpack.Decoder,
    cfg: ClientConfig = .{},
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
    /// Peer's most recent SETTINGS_HEADER_TABLE_SIZE (reader-thread-only).
    peer_header_table_size: u32 = p2.our_header_table_size,

    write_mu: Io.Mutex = .init,
    /// Active outbound write timeout (ms); 0 = unbounded (default for whitebox
    /// struct-literal tests; initialized from `cfg.write_timeout_ms` in `init`).
    write_timeout_ms: u64 = 0,
    /// Guarded by write_mu: poisoned on any write/flush failure or timeout so
    /// later frames cannot land misaligned after a partial write.
    write_broken: bool = false,
    /// Guarded by write_mu: connection-stateful outbound HPACK encoder &
    /// reusable buffer, mutated strictly in on-wire `HEADERS` emission order.
    enc: hpack.EncoderContext = .{},
    hpack_buf: std.ArrayList(u8) = .empty,

    /// Non-blocking control-frame piggyback queue for `readerLoop` / `replenish`
    /// when `write_mu` is actively held by a concurrent `DATA`/`HEADERS` sender.
    /// Lock order: `write_mu -> ctrl_mu` (or `ctrl_mu` standalone on `tryLock` miss).
    ctrl_mu: Io.Mutex = .init,
    ctrl_buf: std.ArrayList(u8) = .empty,
    ctrl_drain: std.ArrayList(u8) = .empty,
    ctrl_hts_min: ?u32 = null,
    ctrl_hts_last: ?u32 = null,
    ctrl_broken: bool = false,

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
    /// Consumed/reclaimed connection-level bytes awaiting half-window batched
    /// stream-0 WINDOW_UPDATE emission. Guarded by `fc_mu`.
    conn_recv_pending: i64 = 0,

    streams_mu: Io.Mutex = .init,
    streams: std.AutoHashMapUnmanaged(u31, *Stream) = .empty,

    /// Lock-free active user op counter + `deinit` wait/seal state (#46):
    ///   bits 0..29 : active in-flight op count
    ///   bit 30     : `op_wait_bit` (`deinit` waiting for count to reach 0)
    ///   bit 31     : `op_sealed_bit` (drained & sealed; rejects late `close()`)
    op_state: std.atomic.Value(u32) = .init(0),

    // Outbound-stream admission (peer SETTINGS_MAX_CONCURRENT_STREAMS). openStream
    // blocks here until a slot frees. Both fields are guarded by admit_mu.
    admit_mu: Io.Mutex = .init,
    admit_cond: Io.Condition = .init,
    peer_max_streams: u32 = std.math.maxInt(u32), // "unlimited" until advertised
    active_streams: u32 = 0,

    keepalive_time_ms: std.atomic.Value(u64) = .init(0),
    keepalive_timeout_ms: std.atomic.Value(u64) = .init(0),
    ping_outstanding: std.atomic.Value(bool) = .init(false),

    dead: std.atomic.Value(bool) = .init(false),
    reader_thread: ?std.Thread = null,
    reader_group: Io.Group = .init,
    reader_done: Io.Event = .unset,
    reader_group_started: std.atomic.Value(bool) = .init(false),
    /// Reusable inbound frame payload scratch buffer (reader-thread-only, #41).
    rx_scratch: std.ArrayList(u8) = .empty,
    /// Event-driven wakeup for the keepalive/teardown watcher on `deinit()`,
    /// `kill()`, and `setKeepalive()` without 50 ms polling or live-read cancellation (#40).
    wake_mu: Io.Mutex = .init,
    wake_cond: Io.Condition = .init,
    ka_gen: u64 = 0,

    // Graceful GOAWAY state packed into one atomic u64 so multiple GOAWAY frames
    // (RFC 9113 §6.8) can update last_stream_id/code concurrently with `goAway()`
    // without a data race or torn read:
    //   bit 63      : seen flag (1 = GOAWAY received)
    //   bits 62..32 : last_stream_id (u31)
    //   bits 31..0  : error code (u32)
    goaway_state: std.atomic.Value(u64) = .init(0),

    const ReaderWake = enum { dead, canceled };
    const ReadChunkOp = union(enum) { work: anyerror!usize, wake: ReaderWake };

    /// Sends the connection preface + initial SETTINGS (+ connection window
    /// enlargement) with default `Config` and starts the reader thread.
    /// Takes `self` by pointer so the reader thread has a stable address.
    pub fn init(self: *Client, io: Io, gpa: std.mem.Allocator, r: *Io.Reader, w: *Io.Writer) !void {
        return self.initWithConfig(io, gpa, r, w, .{});
    }

    fn maxRecvFrame(self: *const Client) u32 {
        return p2.clampMaxFrameSize(self.cfg.max_frame_size);
    }

    fn initHandshakeThunk(self: *Client, settings: *const [24]u8, cwnd: i64) anyerror!void {
        try self.w.writeAll(p2.preface);
        try self.writeFrameLocked(.settings, 0, 0, settings);
        if (cwnd > p2.default_window) {
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, @intCast(cwnd - p2.default_window), .big);
            try self.writeFrameLocked(.window_update, 0, 0, &wu);
        }
        try self.w.flush();
    }

    /// As `init`, with explicit receive-window, frame-size, timeout, and keepalive configuration.
    pub fn initWithConfig(self: *Client, io: Io, gpa: std.mem.Allocator, r: *Io.Reader, w: *Io.Writer, cfg: ClientConfig) !void {
        const cwnd = p2.clampConnWindow(cfg.connection_window_size);
        const iw = p2.clampInitialWindow(cfg.initial_window_size);
        const mfs = p2.clampMaxFrameSize(cfg.max_frame_size);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .r = r,
            .w = w,
            .dec = hpack.Decoder.init(gpa, p2.our_header_table_size),
            .enc = hpack.EncoderContext.initWithMaxSize(cfg.max_encoder_table_size),
            .cfg = cfg,
            .write_timeout_ms = cfg.write_timeout_ms,
            .conn_recv_window = cwnd,
            .keepalive_time_ms = .init(cfg.keepalive_time_ms),
            .keepalive_timeout_ms = .init(cfg.keepalive_timeout_ms),
        };
        errdefer self.dec.deinit();
        {
            self.write_mu.lockUncancelable(self.io);
            defer self.write_mu.unlock(self.io);
            // Advertise ENABLE_PUSH=0, MAX_FRAME_SIZE, INITIAL_WINDOW_SIZE,
            // and MAX_HEADER_LIST_SIZE, plus stream-0 WINDOW_UPDATE if > 65535,
            // coalesced into a single flush.
            var settings: [24]u8 = undefined;
            p2.putSetting(settings[0..6], p2.set_enable_push, 0);
            p2.putSetting(settings[6..12], p2.set_max_frame_size, mfs);
            p2.putSetting(settings[12..18], p2.set_initial_window_size, iw);
            p2.putSetting(settings[18..24], p2.set_max_header_list_size, @intCast(self.dec.max_list_size));
            p2.runTimed(self.io, self.write_timeout_ms, initHandshakeThunk, .{ self, &settings, cwnd }) catch |err| {
                self.write_broken = true;
                return err;
            };
        }
        if (cfg.spawn_reader_thread) {
            self.reader_thread = std.Thread.spawn(.{}, readerLoop, .{self}) catch return error.SystemResources;
        } else {
            // Publish `reader_group_started` BEFORE `concurrent()` spawns
            // `readerLoop` so an instant EOF exit cannot miss setting `reader_done`.
            self.reader_group_started.store(true, .release);
            self.reader_group.concurrent(self.io, readerLoop, .{self}) catch |err| switch (err) {
                error.ConcurrencyUnavailable => {
                    self.reader_group_started.store(false, .release);
                    self.reader_thread = std.Thread.spawn(.{}, readerLoop, .{self}) catch return error.SystemResources;
                },
            };
        }
    }

    fn wakeReader(self: *Client, bump_ka_gen: bool) void {
        self.wake_mu.lockUncancelable(self.io);
        if (bump_ka_gen) self.ka_gen +%= 1;
        self.wake_cond.broadcast(self.io);
        self.wake_mu.unlock(self.io);
    }

    /// Configures keepalive PING cadence and response timeout safely across
    /// threads (the reader thread may already be running). `time_ms == 0`
    /// disables keepalive; `timeout_ms == 0` falls back to `time_ms`.
    pub fn setKeepalive(self: *Client, time_ms: u64, timeout_ms: u64) void {
        self.keepalive_timeout_ms.store(timeout_ms, .release);
        self.keepalive_time_ms.store(time_ms, .release);
        self.wakeReader(true);
    }

    fn hasGoaway(self: *const Client) bool {
        return (self.goaway_state.load(.acquire) >> 63) != 0;
    }

    /// If the peer has sent a GOAWAY, returns its last-processed stream id and
    /// error code; null otherwise. Streams with a higher id were not processed
    /// and are safe to retry on a fresh connection.
    pub fn goAway(self: *Client) ?struct { last_stream_id: u31, code: u32 } {
        const s = self.goaway_state.load(.acquire);
        if ((s >> 63) == 0) return null;
        return .{
            .last_stream_id = @intCast((s >> 32) & 0x7fff_ffff),
            .code = @truncate(s),
        };
    }

    /// Releases the client: stops the reader thread, waits for in-flight
    /// stream/client operations to drain, then frees all remaining streams.
    ///
    /// Lifecycle contract: `deinit` wakes and waits for calls *already* inside
    /// `readEvent`, `send`, `cancel`, `close`, or `openStream`/`openStreamWithBody`
    /// to return. Once `deinit` has begun, callers MUST NOT start any new
    /// `Client` or `Stream` calls — including `Stream.close()` (`deinit` frees
    /// every remaining `*Stream` itself). When separate threads hold `*Stream`
    /// handles with `defer s.close()`, unblock them first (e.g. `s.cancel()`),
    /// `join` those threads, and only then call `deinit()`.
    ///
    /// On concurrent `std.Io` backends, `deinit` wakes the reader watcher and
    /// cancels the in-flight `readVec` so `reader_thread.join` returns promptly
    /// even if the peer is silent. On non-concurrent backends (or custom
    /// readers that do not observe cancellation), the caller must still close
    /// the underlying transport so the blocking read returns.
    pub fn deinit(self: *Client) void {
        // Tell the reader to stop and wake it + any blocked senders/readers so
        // they observe `dead` and return promptly.
        self.dead.store(true, .release);
        self.wakeReader(false);
        self.wakeAdmit(); // release a blocked openStream
        self.wakeAllStreamsAndSenders();
        if (self.reader_thread) |t| {
            t.join();
        } else if (self.reader_group_started.load(.acquire)) {
            self.reader_done.waitUncancelable(self.io);
            self.reader_group.await(self.io) catch {};
        }

        // Lock-free drain & seal (#46): wait for any in-flight user op to
        // finish, then atomically flip `op_sealed_bit` once count == 0 so no
        // late `Stream.close` can enter `removeStream` during table teardown.
        var cur_op = self.op_state.fetchOr(op_wait_bit, .acq_rel) | op_wait_bit;
        while (true) {
            if ((cur_op & op_count_mask) == 0) {
                if (self.op_state.cmpxchgWeak(cur_op, op_sealed_bit, .acq_rel, .acquire)) |actual| {
                    cur_op = actual;
                    continue;
                }
                break;
            }
            self.io.futexWaitUncancelable(u32, &self.op_state.raw, cur_op);
            cur_op = self.op_state.load(.acquire);
        }

        self.ctrl_buf.deinit(self.gpa);
        self.ctrl_drain.deinit(self.gpa);
        self.hpack_buf.deinit(self.gpa);
        self.enc.deinit(self.gpa);
        self.rx_scratch.deinit(self.gpa);
        self.dec.deinit();
        self.streams_mu.lockUncancelable(self.io);
        var streams = self.streams;
        self.streams = .empty;
        self.streams_mu.unlock(self.io);
        var it2 = streams.valueIterator();
        while (it2.next()) |s| {
            s.*.freeQueued(self.gpa);
            self.gpa.destroy(s.*);
        }
        streams.deinit(self.gpa);
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

    /// Lock-free entry into a user-facing client/stream op (`readEvent`,
    /// `readBody`, `send`, `cancel`, `close`, `openStreamWithBody`), rejected
    /// once `deinit` has drained in-flight ops and set `op_sealed_bit` (#46).
    fn tryBeginOp(self: *Client) bool {
        var cur = self.op_state.load(.monotonic);
        while (true) {
            if (cur & op_sealed_bit != 0) return false;
            if (self.op_state.cmpxchgWeak(cur, cur + 1, .acquire, .monotonic)) |actual| {
                cur = actual;
                continue;
            }
            return true;
        }
    }

    fn endOp(self: *Client) void {
        const prev = self.op_state.fetchSub(1, .acq_rel);
        std.debug.assert((prev & op_count_mask) > 0);
        if (prev == (op_wait_bit | 1)) {
            self.io.futexWake(u32, &self.op_state.raw, 1);
        }
    }

    inline fn isSealed(self: *const Client) bool {
        return (self.op_state.load(.acquire) & op_sealed_bit) != 0;
    }

    fn markWriteBrokenLocked(self: *Client) void {
        self.write_broken = true;
        self.ctrl_mu.lockUncancelable(self.io);
        self.ctrl_broken = true;
        self.ctrl_buf.clearRetainingCapacity();
        self.ctrl_hts_min = null;
        self.ctrl_hts_last = null;
        self.ctrl_mu.unlock(self.io);
    }

    fn failCtrlAllocAndUnlock(self: *Client, kill_on_err: bool) void {
        self.ctrl_broken = true;
        self.ctrl_buf.clearRetainingCapacity();
        self.ctrl_hts_min = null;
        self.ctrl_hts_last = null;
        self.ctrl_mu.unlock(self.io);
        if (self.write_mu.tryLock()) {
            self.write_broken = true;
            self.write_mu.unlock(self.io);
        }
        if (kill_on_err) self.kill();
    }

    fn writeFrameLocked(self: *Client, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        var hb: [9]u8 = undefined;
        p2.putHeader(&hb, payload.len, ftype, flags, sid);
        if (payload.len > 0) {
            var vecs = [_][]const u8{ &hb, payload };
            try self.w.writeVecAll(&vecs);
        } else {
            try self.w.writeAll(&hb);
        }
    }

    fn writeHeaderBlockLocked(self: *Client, sid: u31, end_stream: bool, max_frame: usize, block: []const u8) !void {
        const es: u8 = if (end_stream) p2.flag_end_stream else 0;
        if (block.len <= max_frame) {
            try self.writeFrameLocked(.headers, p2.flag_end_headers | es, sid, block);
        } else {
            try self.writeFrameLocked(.headers, es, sid, block[0..max_frame]);
            var off: usize = max_frame;
            while (off < block.len) {
                const end = @min(off + max_frame, block.len);
                const last = end == block.len;
                try self.writeFrameLocked(.continuation, if (last) p2.flag_end_headers else 0, sid, block[off..end]);
                off = end;
            }
        }
    }

    fn drainCtrlToBufferLocked(self: *Client) !void {
        while (true) {
            self.ctrl_mu.lockUncancelable(self.io);
            if (self.ctrl_broken) {
                self.ctrl_mu.unlock(self.io);
                return error.WriteFailed;
            }
            if (self.ctrl_buf.items.len == 0) {
                self.ctrl_mu.unlock(self.io);
                return;
            }
            std.mem.swap(std.ArrayList(u8), &self.ctrl_buf, &self.ctrl_drain);
            if (self.ctrl_hts_last) |last_hts| {
                self.enc.notePeerHeaderTableSize(self.ctrl_hts_min orelse last_hts, last_hts);
                self.ctrl_hts_min = null;
                self.ctrl_hts_last = null;
            }
            self.ctrl_mu.unlock(self.io);
            defer self.ctrl_drain.clearRetainingCapacity();
            try self.w.writeAll(self.ctrl_drain.items);
        }
    }

    fn writeAndFlushCtrlSliceThunk(w: *Io.Writer, bytes: []const u8) anyerror!void {
        if (bytes.len > 0) try w.writeAll(bytes);
        try w.flush();
    }

    /// Drains any control frames queued while `write_mu` was held, flushes
    /// under `write_timeout_ms`, and performs hand-over-hand unlock of
    /// `write_mu` under `ctrl_mu` so no queued control frame is ever stranded.
    fn finishWriteAndUnlock(self: *Client, write_err: ?anyerror, kill_on_err: bool) !void {
        if (write_err) |err| {
            self.markWriteBrokenLocked();
            self.write_mu.unlock(self.io);
            if (kill_on_err) self.kill();
            return err;
        }
        while (true) {
            self.ctrl_mu.lockUncancelable(self.io);
            if (self.ctrl_broken) {
                self.ctrl_mu.unlock(self.io);
                self.markWriteBrokenLocked();
                self.write_mu.unlock(self.io);
                if (kill_on_err) self.kill();
                return error.WriteFailed;
            }
            if (self.ctrl_buf.items.len == 0) {
                self.write_mu.unlock(self.io);
                self.ctrl_mu.unlock(self.io);
                return;
            }
            std.mem.swap(std.ArrayList(u8), &self.ctrl_buf, &self.ctrl_drain);
            if (self.ctrl_hts_last) |last_hts| {
                self.enc.notePeerHeaderTableSize(self.ctrl_hts_min orelse last_hts, last_hts);
                self.ctrl_hts_min = null;
                self.ctrl_hts_last = null;
            }
            self.ctrl_mu.unlock(self.io);
            const err_opt: ?anyerror = if (p2.runTimed(self.io, self.write_timeout_ms, writeAndFlushCtrlSliceThunk, .{ self.w, self.ctrl_drain.items })) |_|
                null
            else |e|
                e;
            self.ctrl_drain.clearRetainingCapacity();
            if (err_opt) |err| {
                self.markWriteBrokenLocked();
                self.write_mu.unlock(self.io);
                if (kill_on_err) self.kill();
                return err;
            }
        }
    }

    fn writeSingleFrameThunk(self: *Client, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8) anyerror!void {
        try self.drainCtrlToBufferLocked();
        try self.writeFrameLocked(ftype, flags, sid, payload);
        try self.drainCtrlToBufferLocked();
        try self.w.flush();
    }

    fn writeControlFrame(self: *Client, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8, hts_update: ?HtsUpdate, kill_on_err: bool) !void {
        if (self.write_mu.tryLock()) {
            if (self.write_broken) {
                self.write_mu.unlock(self.io);
                return error.WriteFailed;
            }
            const err_opt: ?anyerror = if (p2.runTimed(self.io, self.write_timeout_ms, writeSingleFrameThunk, .{ self, ftype, flags, sid, payload })) |_|
                null
            else |e|
                e;
            if (err_opt == null) {
                if (hts_update) |u| self.enc.notePeerHeaderTableSize(u.min, u.last);
            }
            return self.finishWriteAndUnlock(err_opt, kill_on_err);
        }
        self.ctrl_mu.lockUncancelable(self.io);
        if (self.ctrl_broken) {
            self.ctrl_mu.unlock(self.io);
            return error.WriteFailed;
        }
        var hb: [9]u8 = undefined;
        p2.putHeader(&hb, payload.len, ftype, flags, sid);
        self.ctrl_buf.ensureUnusedCapacity(self.gpa, 9 + payload.len) catch |err| {
            self.failCtrlAllocAndUnlock(kill_on_err);
            return err;
        };
        self.ctrl_buf.appendSliceAssumeCapacity(&hb);
        if (payload.len > 0) self.ctrl_buf.appendSliceAssumeCapacity(payload);
        if (hts_update) |u| {
            self.ctrl_hts_min = if (self.ctrl_hts_min) |prev| @min(prev, u.min) else u.min;
            self.ctrl_hts_last = u.last;
        }
        self.ctrl_mu.unlock(self.io);

        if (self.write_mu.tryLock()) {
            if (self.write_broken) {
                self.write_mu.unlock(self.io);
                return error.WriteFailed;
            }
            return self.finishWriteAndUnlock(null, kill_on_err);
        }
    }

    fn ackPeerSettings(self: *Client, hts_update: ?HtsUpdate) !void {
        return self.writeControlFrame(.settings, p2.flag_ack, 0, "", hts_update, true);
    }

    fn writeFrame(self: *Client, ftype: p2.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        const kill_on_err = self.reader_thread != null or self.reader_group_started.load(.acquire);
        return self.writeControlFrame(ftype, flags, sid, payload, null, kill_on_err);
    }

    /// Writes `data` as one or more DATA frames (each <= `max_frame`) without
    /// flushing. Caller holds `write_mu`. When `data.len == 0` and `end_stream`
    /// is true, emits a single 0-byte DATA(END_STREAM) frame.
    fn writeDataFramesLocked(self: *Client, sid: u31, data: []const u8, end_stream: bool, max_frame: usize) !void {
        std.debug.assert(max_frame > 0);
        if (data.len == 0) {
            if (end_stream) try self.writeFrameLocked(.data, p2.flag_end_stream, sid, "");
            return;
        }
        var off: usize = 0;
        while (off < data.len) {
            const chunk_len = @min(data.len - off, max_frame);
            const is_last = off + chunk_len == data.len;
            const flags: u8 = if (end_stream and is_last) p2.flag_end_stream else 0;
            try self.writeFrameLocked(.data, flags, sid, data[off .. off + chunk_len]);
            off += chunk_len;
        }
    }

    fn writeStreamDataBatchThunk(self: *Client, sid: u31, data: []const u8, end_stream: bool, max: usize) anyerror!void {
        try self.drainCtrlToBufferLocked();
        try self.writeDataFramesLocked(sid, data, end_stream, max);
        try self.drainCtrlToBufferLocked();
        try self.w.flush();
    }

    fn writeDataForStream(self: *Client, st: *Stream, data: []const u8, end_stream: bool) !void {
        self.write_mu.lockUncancelable(self.io);
        if (self.dead.load(.acquire) or self.write_broken) {
            self.write_mu.unlock(self.io);
            return error.ConnectionClosed;
        }
        self.drainCtrlToBufferLocked() catch |err| {
            return self.finishWriteAndUnlock(err, true);
        };
        if (st.aborted.load(.acquire)) {
            try self.finishWriteAndUnlock(null, true);
            return error.StreamReset;
        }
        if (st.local_closed.load(.acquire)) {
            try self.finishWriteAndUnlock(null, true);
            return error.StreamClosed;
        }
        const max: usize = self.peer_max_frame.load(.acquire);
        const err_opt: ?anyerror = if (p2.runTimed(self.io, self.write_timeout_ms, writeStreamDataBatchThunk, .{ self, st.id, data, end_stream, max })) |_|
            null
        else |e|
            e;
        if (err_opt == null and end_stream) st.local_closed.store(true, .release);
        try self.finishWriteAndUnlock(err_opt, true);
    }

    /// Returns true if `sid` is in the idle state (never initiated: even push
    /// stream id with ENABLE_PUSH=0, or odd id not yet allocated by openStream).
    fn isIdleStream(self: *Client, sid: u31) bool {
        if (sid == 0) return false;
        if (sid % 2 == 0) return true;
        self.write_mu.lockUncancelable(self.io);
        const idle = sid >= self.next_id;
        self.write_mu.unlock(self.io);
        return idle;
    }

    /// Best-effort GOAWAY(last_stream_id=0, code). The client only observes
    /// peer-initiated (even/push) streams — disabled — so the last id is 0.
    fn sendGoaway(self: *Client, code: p2.ErrorCode) void {
        var p: [8]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], 0, .big);
        std.mem.writeInt(u32, p[4..8], @backingInt(code), .big);
        self.writeFrame(.goaway, 0, 0, &p) catch {};
    }

    fn writeOpenStreamThunk(
        self: *Client,
        sid: u31,
        max: usize,
        block: []const u8,
        initial_body: []const u8,
        hdr_end_stream: bool,
        data_end_stream: bool,
    ) anyerror!void {
        try self.drainCtrlToBufferLocked();
        try self.writeHeaderBlockLocked(sid, hdr_end_stream, max, block);
        if (initial_body.len > 0) {
            try self.writeDataFramesLocked(sid, initial_body, data_end_stream, max);
        }
        try self.drainCtrlToBufferLocked();
        try self.w.flush();
    }

    fn estimateMaxEncodedBytes(head: RequestHead) usize {
        // Upper bound on non-indexed HPACK encoding: 20 bytes of integer prefix
        // overhead per field + raw octets + up to 20 bytes for table-size updates.
        var total: usize = 20;
        total +|= head.method.len +| head.scheme.len +| head.path.len +| head.authority.len +| 80;
        for (head.headers) |h| {
            total +|= h.name.len +| h.value.len +| 20;
        }
        return total;
    }

    /// Opens a new stream, sending the request HEADERS. Returns a handle for
    /// send/readEvent/cancel. `end_stream` half-closes immediately (bodyless).
    /// For requests with an initial body payload (e.g. gRPC unary RPCs or
    /// known-body POSTs), prefer `openStreamWithBody` to coalesce HEADERS +
    /// initial DATA (+ END_STREAM) into a single flush.
    pub fn openStream(self: *Client, head: RequestHead, end_stream: bool) !*Stream {
        return self.openStreamWithBody(head, "", end_stream);
    }

    /// Opens a new stream and coalesces request HEADERS + initial DATA (+
    /// END_STREAM when the full body fits in the current flow-control window
    /// and batch cap) into a single `write_mu` lock and single `w.flush()` (#44).
    ///
    /// Encodes request headers with `self.enc` inside `write_mu` into reusable
    /// `self.hpack_buf` so HPACK dynamic-table mutations strictly match wire order
    /// with zero per-stream `ArenaAllocator` overhead.
    pub fn openStreamWithBody(self: *Client, head: RequestHead, body: []const u8, end_stream: bool) !*Stream {
        if (!self.tryBeginOp()) return error.ConnectionClosed;
        defer self.endOp();
        if (self.dead.load(.acquire)) return error.ConnectionClosed;

        // Pre-validate huge header sets (`> ~256 KiB` worst case) using stateless
        // encoding BEFORE acquiring slots or mutating `self.enc.dyn`.
        var huge_stateless: std.ArrayList(u8) = .empty;
        defer huge_stateless.deinit(self.gpa);
        const use_stateless = estimateMaxEncodedBytes(head) > max_header_block - 64;
        if (use_stateless) {
            try hpack.Encoder.encodeRequest(self.gpa, &huge_stateless, head.method, head.scheme, head.path, head.authority, head.headers);
            if (huge_stateless.items.len > max_header_block - 20) return error.HeadersTooLarge;
        }

        // Admission: block until a concurrency slot is free (peer
        // MAX_CONCURRENT_STREAMS), or bail if the connection is closing.
        self.admit_mu.lockUncancelable(self.io);
        while (true) {
            if (self.dead.load(.acquire)) {
                self.admit_mu.unlock(self.io);
                return error.ConnectionClosed;
            }
            if (self.hasGoaway()) {
                self.admit_mu.unlock(self.io);
                return error.GoingAway;
            }
            if (self.active_streams < self.peer_max_streams) break;
            self.admit_cond.waitUncancelable(self.io, &self.admit_mu);
        }
        self.active_streams += 1;
        self.admit_mu.unlock(self.io);

        self.write_mu.lockUncancelable(self.io);
        if (self.write_broken) {
            self.write_mu.unlock(self.io);
            self.admitCancel();
            return error.ConnectionClosed;
        }
        // Drain any queued control frames (including SETTINGS(ACK) carrying
        // peer `SETTINGS_HEADER_TABLE_SIZE` updates) BEFORE encoding `HEADERS`!
        self.drainCtrlToBufferLocked() catch |err| {
            self.admitCancel();
            self.finishWriteAndUnlock(err, true) catch {};
            return error.ConnectionClosed;
        };

        const sid = self.next_id;
        const next_sid = std.math.add(u31, sid, 2) catch {
            self.write_mu.unlock(self.io);
            self.admitCancel();
            return error.StreamIdsExhausted;
        };

        const st = self.gpa.create(Stream) catch {
            self.write_mu.unlock(self.io);
            self.admitCancel();
            return error.OutOfMemory;
        };
        st.* = .{
            .client = self,
            .id = sid,
            .send_window = 0,
            .recv_window = p2.clampInitialWindow(self.cfg.initial_window_size),
            .local_closed = .init(false),
            .is_head_request = std.mem.eql(u8, head.method, "HEAD"),
        };
        const max: usize = self.peer_max_frame.load(.acquire);
        const batch_cap: usize = @max(max_write_batch, max);
        var first_chunk: usize = 0;
        self.streams_mu.lockUncancelable(self.io);
        if (self.dead.load(.acquire)) {
            self.streams_mu.unlock(self.io);
            self.write_mu.unlock(self.io);
            self.releaseSlot(st);
            self.gpa.destroy(st);
            return error.ConnectionClosed;
        }
        if (self.hasGoaway()) {
            self.streams_mu.unlock(self.io);
            self.write_mu.unlock(self.io);
            self.releaseSlot(st);
            self.gpa.destroy(st);
            return error.GoingAway;
        }
        self.streams.put(self.gpa, sid, st) catch {
            self.streams_mu.unlock(self.io);
            self.write_mu.unlock(self.io);
            self.releaseSlot(st);
            self.gpa.destroy(st);
            return error.OutOfMemory;
        };
        self.next_id = next_sid;
        {
            self.send_mu.lockUncancelable(self.io);
            defer self.send_mu.unlock(self.io);
            st.send_window = self.peer_initial_window.load(.acquire);
            if (body.len > 0) {
                const avail = @min(st.send_window, self.conn_send_window);
                if (avail > 0) {
                    const want: i64 = @min(@as(i64, @intCast(body.len)), @min(avail, @as(i64, @intCast(batch_cap))));
                    st.send_window -= want;
                    self.conn_send_window -= want;
                    first_chunk = @intCast(want);
                }
            }
        }
        const all_sent = first_chunk == body.len;
        if (end_stream and all_sent) st.local_closed.store(true, .release);
        self.streams_mu.unlock(self.io);

        self.hpack_buf.clearRetainingCapacity();
        const enc_res = if (use_stateless) blk: {
            if (self.enc.pending_target_size) |target| {
                const min_s = self.enc.pending_min_size orelse target;
                var tbuf: [10]u8 = undefined;
                if (min_s < target) {
                    self.hpack_buf.appendSlice(self.gpa, hpack.Encoder.encodeTableSizeUpdate(min_s, &tbuf)) catch |e| break :blk @as(anyerror!void, e);
                    self.enc.dyn.setMaxSize(min_s);
                }
                self.hpack_buf.appendSlice(self.gpa, hpack.Encoder.encodeTableSizeUpdate(target, &tbuf)) catch |e| break :blk @as(anyerror!void, e);
                self.enc.dyn.setMaxSize(target);
                self.enc.pending_min_size = null;
                self.enc.pending_target_size = null;
            }
            break :blk @as(anyerror!void, self.hpack_buf.appendSlice(self.gpa, huge_stateless.items));
        } else self.enc.encodeRequest(self.gpa, &self.hpack_buf, head.method, head.scheme, head.path, head.authority, head.headers);

        if (enc_res) |_| {} else |enc_err| {
            self.finishWriteAndUnlock(enc_err, true) catch {};
            self.removeStream(sid);
            return if (enc_err == error.OutOfMemory) error.OutOfMemory else error.ConnectionClosed;
        }

        const hdr_end_stream = end_stream and body.len == 0;
        const open_err: ?anyerror = if (p2.runTimed(self.io, self.write_timeout_ms, writeOpenStreamThunk, .{
            self,
            sid,
            max,
            self.hpack_buf.items,
            body[0..first_chunk],
            hdr_end_stream,
            end_stream and all_sent,
        })) |_|
            null
        else |e|
            e;
        self.finishWriteAndUnlock(open_err, true) catch {
            self.removeStream(sid); // releases the slot
            return error.ConnectionClosed;
        };

        if (all_sent) {
            if (end_stream) self.noteEnd(st, true, false);
            return st;
        }
        // Remaining body bytes exceed the initial window or batch cap: stream
        // them via `Stream.send` (which also handles END_STREAM + noteEnd).
        // On failure, close & reclaim `st` since the caller never receives it.
        st.send(body[first_chunk..], end_stream) catch |err| {
            st.close();
            return err;
        };
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
        if (self.isSealed()) {
            self.streams_mu.unlock(self.io);
            return;
        }
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
                // Flush both unconsumed DATA and any remaining sub-threshold
                // conn_recv_pending so closing a stream never strands peer credit.
                const conn_amt = self.creditConn(owed, true);
                self.writeWindowUpdates(conn_amt, 0, 0);
            }
        } else {
            self.streams_mu.unlock(self.io);
        }
    }

    // --- reader thread ------------------------------------------------------

    /// Borrows a reusable reader-thread scratch buffer of length `needed`,
    /// growing on demand (starting at 16 KiB) up to `maxRecvFrame()` (#41).
    fn borrowScratch(self: *Client, needed: usize) ![]u8 {
        if (needed == 0) return &.{};
        if (self.rx_scratch.capacity < needed) {
            try self.rx_scratch.ensureTotalCapacity(self.gpa, @max(@as(usize, p2.our_max_frame_size), needed));
        }
        self.rx_scratch.items.len = needed;
        return self.rx_scratch.items;
    }

    fn readerLoop(self: *Client) void {
        defer if (self.reader_group_started.load(.acquire)) self.reader_done.set(self.io);
        var peer_settings_seen = false;
        while (!self.dead.load(.acquire)) {
            var hb: [9]u8 = undefined;
            self.readFrameHeader(&hb) catch {
                self.kill();
                return;
            };
            const fh = p2.parseHeader(&hb);
            if (fh.length > self.maxRecvFrame()) {
                self.sendGoaway(.frame_size_error);
                self.kill();
                return;
            }
            const payload = self.borrowScratch(fh.length) catch {
                self.kill();
                return;
            };
            if (payload.len > 0) {
                self.readBytesBounded(payload) catch {
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
            // RFC 9113 §3.4: the server connection preface MUST be a non-ACK
            // SETTINGS frame as the first frame sent on the connection.
            if (!peer_settings_seen) {
                if (fh.ftype != .settings or (fh.flags & p2.flag_ack != 0)) {
                    self.sendGoaway(.protocol_error);
                    self.kill();
                    return;
                }
                peer_settings_seen = true;
            }
            self.handle(fh, payload) catch {
                self.kill();
                return;
            };
        }
    }

    /// Caller holds `self.send_mu`. Wakes `st` whether parked on its per-stream
    /// `send_cond` or on the connection-wide `send_cond` (`O(1)` targeted wakeup).
    fn wakeStreamSenderLocked(self: *Client, st: *Stream) void {
        st.send_cond.broadcast(self.io);
        if (st.waiting_conn_window) self.send_cond.broadcast(self.io);
    }

    fn wakeStreamSender(self: *Client, st: *Stream) void {
        self.send_mu.lockUncancelable(self.io);
        self.wakeStreamSenderLocked(st);
        self.send_mu.unlock(self.io);
    }

    /// Wakes every stream receiver and sender on connection teardown.
    /// Lock order: `streams_mu -> send_mu` and `streams_mu -> recv_mu`.
    fn wakeAllStreamsAndSenders(self: *Client) void {
        self.streams_mu.lockUncancelable(self.io);
        self.send_mu.lockUncancelable(self.io);
        self.send_cond.broadcast(self.io);
        var it_s = self.streams.valueIterator();
        while (it_s.next()) |s| s.*.send_cond.broadcast(self.io);
        self.send_mu.unlock(self.io);
        var it_r = self.streams.valueIterator();
        while (it_r.next()) |s| s.*.shutdown(self.io);
        self.streams_mu.unlock(self.io);
    }

    /// Wakes every opener blocked at `MAX_CONCURRENT_STREAMS`. Holding
    /// `admit_mu` across the broadcast closes the lost-wake window against
    /// `openStream` checking `dead`/`goaway_state` before waiting.
    fn wakeAdmit(self: *Client) void {
        self.admit_mu.lockUncancelable(self.io);
        self.admit_cond.broadcast(self.io);
        self.admit_mu.unlock(self.io);
    }

    /// Marks the connection dead and releases every blocked stream/sender.
    fn kill(self: *Client) void {
        self.dead.store(true, .release);
        self.wakeReader(false);
        self.wakeAdmit(); // release a blocked openStream
        self.wakeAllStreamsAndSenders();
    }

    fn handle(self: *Client, fh: p2.ParsedHeader, payload: []const u8) !void {
        switch (fh.ftype) {
            .settings => if (fh.flags & p2.flag_ack == 0) {
                const hts_update = try self.applyPeerSettings(payload);
                try self.ackPeerSettings(hts_update);
            },
            .ping => if (fh.flags & p2.flag_ack == 0) try self.writeFrame(.ping, p2.flag_ack, 0, payload),
            .window_update => try self.handleWindowUpdate(fh.sid, payload),
            .goaway => {
                if (payload.len < 8) {
                    self.sendGoaway(.protocol_error);
                    self.kill();
                    return error.ProtocolError;
                }
                const raw_last_id: u31 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
                const code = std.mem.readInt(u32, payload[4..8], .big);
                // Keep last_stream_id non-increasing across multiple GOAWAYs
                // (RFC 9113 §6.8) and publish atomically so concurrent goAway()
                // calls never race with a second GOAWAY frame.
                const prev = self.goaway_state.load(.monotonic);
                const last_id: u31 = if ((prev >> 63) != 0)
                    @min(@as(u31, @intCast((prev >> 32) & 0x7fff_ffff)), raw_last_id)
                else
                    raw_last_id;
                const packed_state: u64 = (@as(u64, 1) << 63) | (@as(u64, last_id) << 32) | @as(u64, code);
                self.goaway_state.store(packed_state, .release);
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
                        self.wakeStreamSender(s); // release refused sender (`streams_mu -> send_mu`)
                        self.noteEnd(s, true, true); // refused: frees its slot
                    }
                }
                self.streams_mu.unlock(self.io);
                self.wakeAdmit(); // and a blocked openStream
            },
            .rst_stream => {
                // RFC 9113 §6.4: RST_STREAM on an idle stream is a connection PROTOCOL_ERROR.
                if (self.isIdleStream(fh.sid)) {
                    self.sendGoaway(.protocol_error);
                    return error.ProtocolError;
                }
                const code: u32 = if (payload.len >= 4) std.mem.readInt(u32, payload[0..4], .big) else 0;
                self.streams_mu.lockUncancelable(self.io);
                if (self.streams.get(fh.sid)) |st| {
                    st.aborted.store(true, .release);
                    st.recv_mu.lockUncancelable(self.io);
                    st.reset = code;
                    st.recv_cond.broadcast(self.io);
                    st.recv_mu.unlock(self.io);
                    self.wakeStreamSender(st); // wake only this stream's sender (`O(1)`)
                    self.noteEnd(st, true, true); // reset frees its slot
                }
                self.streams_mu.unlock(self.io);
                self.wakeAdmit();
            },
            .headers => {
                const frag = stripHeaderPadding(fh, payload) orelse {
                    self.sendGoaway(.protocol_error);
                    self.kill();
                    return error.ProtocolError;
                };
                if (frag.len > max_header_block) {
                    self.sendGoaway(.enhance_your_calm);
                    self.kill();
                    return error.ProtocolError;
                }
                var cont_block: std.ArrayList(u8) = .empty;
                defer cont_block.deinit(self.gpa);
                // Fast path (`END_HEADERS` set): borrow `frag` directly out of
                // `self.rx_scratch` with zero `ArrayList` allocation or copy.
                const hdr_block: []const u8 = if (fh.flags & p2.flag_end_headers != 0)
                    frag
                else blk: {
                    try cont_block.appendSlice(self.gpa, frag);
                    try self.readContinuations(fh.sid, &cont_block);
                    break :blk cont_block.items;
                };
                const hs = self.dec.decode(self.gpa, hdr_block) catch |err| {
                    // RFC 9113 §4.3: HPACK decode failure is a connection COMPRESSION_ERROR.
                    self.sendGoaway(if (err == error.OutOfMemory) .internal_error else .compression_error);
                    return err;
                };
                try self.deliver(fh.sid, true, hs, &[_]u8{}, fh.flags & p2.flag_end_stream != 0, 0);
            },
            .data => {
                // Flow control counts the whole frame (pad octet + data + pad).
                // We credit it only when the caller consumes the DATA (see
                // readEvent / readBody) so an unread stream backpressures the peer.
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
                try self.deliver(fh.sid, false, &[_]hpack.Header{}, body, fh.flags & p2.flag_end_stream != 0, fc_cost);
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
    fn deliver(self: *Client, sid: u31, is_headers: bool, hs: []const Header, bytes: []const u8, end_stream: bool, fc_cost: u32) !void {
        self.streams_mu.lockUncancelable(self.io);
        const st = self.streams.get(sid);
        if (st) |s| {
            s.recv_mu.lockUncancelable(self.io);
            if (s.reset != null or s.cancelled or s.goaway_refused) {
                s.recv_mu.unlock(self.io);
                self.streams_mu.unlock(self.io);
                if (is_headers) freeHeaders(self.gpa, hs);
                // Stream is already closed locally (e.g. reset by us on a
                // WINDOW_UPDATE overflow or cancelled): ignore later inbound
                // frames, but still return the connection-level window credit
                // deducted on arrival (RFC 7540 §6.9).
                if (fc_cost > 0) {
                    const conn_amt = self.creditConn(fc_cost, true);
                    self.writeWindowUpdates(conn_amt, 0, 0);
                }
                return;
            }
            const item: Queued = if (is_headers) .{ .headers = hs } else .{ .data = .{ .len = @intCast(bytes.len), .fc_cost = fc_cost } };
            var rst: ?p2.ErrorCode = null;
            if (s.remote_closed) {
                // RFC 9113 §5.1: DATA/HEADERS after END_STREAM is a connection
                // STREAM_CLOSED error if the stream is fully closed, or a stream
                // STREAM_CLOSED error if still half-closed (remote).
                if (s.local_closed.load(.acquire)) {
                    s.recv_mu.unlock(self.io);
                    self.streams_mu.unlock(self.io);
                    if (is_headers) freeHeaders(self.gpa, hs);
                    self.sendGoaway(.stream_closed);
                    return error.ProtocolError;
                }
                rst = .stream_closed;
            } else if (is_headers) {
                if (!validateStreamHeaders(s, hs, end_stream)) {
                    rst = .protocol_error;
                }
            } else {
                if (s.resp_phase != .expect_body_or_trailers) {
                    rst = .protocol_error;
                } else {
                    s.recv_window -= @as(i64, fc_cost);
                    if (s.recv_window < 0) {
                        s.recv_window += @as(i64, fc_cost); // nothing delivered: no stream credit owed
                        rst = .flow_control_error;
                    } else {
                        if (std.math.add(u64, s.rx_body_bytes, bytes.len)) |new_total| {
                            if (s.resp_content_length) |cl| {
                                if (new_total > cl or (end_stream and new_total != cl)) {
                                    s.recv_window += @as(i64, fc_cost);
                                    rst = .protocol_error;
                                } else {
                                    s.rx_body_bytes = new_total;
                                }
                            } else {
                                s.rx_body_bytes = new_total;
                            }
                        } else |_| {
                            s.recv_window += @as(i64, fc_cost);
                            rst = .protocol_error;
                        }
                    }
                }
            }
            if (rst == null) {
                var oom = false;
                var rx_appended = false;
                if (!is_headers and bytes.len > 0) {
                    s.rx_buf.appendSlice(self.gpa, bytes) catch {
                        oom = true;
                    };
                    if (!oom) rx_appended = true;
                }
                if (!oom) {
                    s.queue.append(self.gpa, item) catch {
                        if (rx_appended) s.rx_buf.len -= bytes.len;
                        oom = true;
                    };
                }
                if (!oom) {
                    s.end_flags.append(self.gpa, end_stream) catch {
                        s.queue.items.len -= 1;
                        if (rx_appended) s.rx_buf.len -= bytes.len;
                        oom = true;
                    };
                }
                if (!oom) {
                    s.is_headers.append(self.gpa, is_headers) catch {
                        s.queue.items.len -= 1;
                        s.end_flags.items.len -= 1;
                        if (rx_appended) s.rx_buf.len -= bytes.len;
                        oom = true;
                    };
                }
                if (oom) {
                    if (is_headers) freeHeaders(self.gpa, hs);
                    s.recv_mu.unlock(self.io);
                    self.streams_mu.unlock(self.io);
                    return error.OutOfMemory;
                }
            } else {
                if (is_headers) freeHeaders(self.gpa, hs);
            }
            if (rst) |code| {
                s.aborted.store(true, .release);
                s.reset = @backingInt(code);
                s.recv_cond.broadcast(self.io);
                s.recv_mu.unlock(self.io);
                self.wakeStreamSender(s); // release a sender blocked on this stream's window
                self.noteEnd(s, true, true); // reset frees its slot
                self.streams_mu.unlock(self.io);
                var p: [4]u8 = undefined;
                std.mem.writeInt(u32, &p, @backingInt(code), .big);
                self.writeFrame(.rst_stream, 0, sid, &p) catch {};
                // The frame is dropped: return the connection window we
                // deducted on arrival, and keep our ledger in step with the
                // credit we grant (RFC 7540 §6.9 — conn flow control spans
                // reset/closed streams).
                if (fc_cost > 0) {
                    const conn_amt = self.creditConn(fc_cost, true);
                    self.writeWindowUpdates(conn_amt, 0, 0);
                }
                return;
            }
            if (end_stream) s.remote_closed = true;
            s.recv_cond.broadcast(self.io);
            s.recv_mu.unlock(self.io);
            if (end_stream) self.noteEnd(s, false, true); // remote half-closed
            self.streams_mu.unlock(self.io);
        } else {
            self.streams_mu.unlock(self.io);
            const idle = self.isIdleStream(sid);
            if (is_headers) {
                freeHeaders(self.gpa, hs);
                // RFC 9113 §5.1 / §5.1.1: HEADERS on an idle stream (even push
                // id with ENABLE_PUSH=0, or client id never opened) is a
                // connection PROTOCOL_ERROR. Frames for a stream we already
                // closed/reset may still arrive in-flight and are ignored.
                if (idle) {
                    self.sendGoaway(.protocol_error);
                    return error.ProtocolError;
                }
            } else {
                // DATA on an idle stream (even push id or >= next_id) is a
                // connection PROTOCOL_ERROR (RFC 9113 §5.1).
                if (idle) {
                    self.sendGoaway(.protocol_error);
                    return error.ProtocolError;
                }
                // An odd id below next_id that is no longer open was closed: a
                // stream error — RST STREAM_CLOSED, keeping the connection.
                var p: [4]u8 = undefined;
                std.mem.writeInt(u32, &p, @backingInt(p2.ErrorCode.stream_closed), .big);
                self.writeFrame(.rst_stream, 0, sid, &p) catch {};
            }
            // Stream already gone, but the connection window must still be
            // returned for its DATA (RFC 7540 §6.9 — conn flow control spans
            // closed streams), or a hostile peer could leak it to zero. The
            // ledger grows with the credit granted, same as replenish.
            if (fc_cost > 0) {
                const conn_amt = self.creditConn(fc_cost, true);
                self.writeWindowUpdates(conn_amt, 0, 0);
            }
        }
    }

    /// Records `amt` consumed/reclaimed connection-level bytes and returns the
    /// stream-0 WINDOW_UPDATE increment to emit. When `flush_all` is false
    /// (stream still receiving), batches until half of `connection_window_size`;
    /// when `flush_all` is true (stream ended or removed), flushes all pending
    /// connection credit so sub-threshold credit is never stranded on idle.
    fn creditConn(self: *Client, amt: u32, flush_all: bool) u32 {
        self.fc_mu.lockUncancelable(self.io);
        defer self.fc_mu.unlock(self.io);
        self.conn_recv_pending += @as(i64, amt);
        if (self.conn_recv_pending <= 0) return 0;
        const threshold = @max(@as(i64, 1), p2.clampConnWindow(self.cfg.connection_window_size) >> 1);
        if (flush_all or self.conn_recv_pending >= threshold) {
            const room: i64 = 0x7fff_ffff - self.conn_recv_window;
            const grant = @min(self.conn_recv_pending, @max(@as(i64, 0), room));
            if (grant > 0) {
                self.conn_recv_window += grant;
                self.conn_recv_pending -= grant;
                return @intCast(grant);
            }
        }
        return 0;
    }

    /// Coalesces connection-level and stream-level WINDOW_UPDATE frames into a
    /// single `write_mu` lock acquisition and a single `w.flush()` (#39).
    fn writeWindowUpdatesThunk(self: *Client, conn_amt: u32, sid: u31, stream_amt: u32) anyerror!void {
        try self.drainCtrlToBufferLocked();
        if (conn_amt > 0) {
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, conn_amt, .big);
            try self.writeFrameLocked(.window_update, 0, 0, &wu);
        }
        if (stream_amt > 0) {
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, stream_amt, .big);
            try self.writeFrameLocked(.window_update, 0, sid, &wu);
        }
        try self.drainCtrlToBufferLocked();
        try self.w.flush();
    }

    fn writeWindowUpdates(self: *Client, conn_amt: u32, sid: u31, stream_amt: u32) void {
        if (conn_amt == 0 and stream_amt == 0) return;
        const kill_on_err = self.reader_thread != null or self.reader_group_started.load(.acquire);
        if (self.write_mu.tryLock()) {
            if (self.write_broken) {
                self.write_mu.unlock(self.io);
                return;
            }
            const err_opt: ?anyerror = if (p2.runTimed(self.io, self.write_timeout_ms, writeWindowUpdatesThunk, .{ self, conn_amt, sid, stream_amt })) |_|
                null
            else |e|
                e;
            self.finishWriteAndUnlock(err_opt, kill_on_err) catch {};
            return;
        }
        self.ctrl_mu.lockUncancelable(self.io);
        if (self.ctrl_broken) {
            self.ctrl_mu.unlock(self.io);
            return;
        }
        const count: usize = @as(usize, if (conn_amt > 0) 13 else 0) + @as(usize, if (stream_amt > 0) 13 else 0);
        self.ctrl_buf.ensureUnusedCapacity(self.gpa, count) catch {
            // Local receive-window ledgers were already incremented; tear down
            // rather than silently dropping the peer's WINDOW_UPDATE credit.
            self.failCtrlAllocAndUnlock(kill_on_err);
            return;
        };
        if (conn_amt > 0) {
            var hb: [9]u8 = undefined;
            var wu: [4]u8 = undefined;
            p2.putHeader(&hb, 4, .window_update, 0, 0);
            std.mem.writeInt(u32, &wu, conn_amt, .big);
            self.ctrl_buf.appendSliceAssumeCapacity(&hb);
            self.ctrl_buf.appendSliceAssumeCapacity(&wu);
        }
        if (stream_amt > 0) {
            var hb: [9]u8 = undefined;
            var wu: [4]u8 = undefined;
            p2.putHeader(&hb, 4, .window_update, 0, sid);
            std.mem.writeInt(u32, &wu, stream_amt, .big);
            self.ctrl_buf.appendSliceAssumeCapacity(&hb);
            self.ctrl_buf.appendSliceAssumeCapacity(&wu);
        }
        self.ctrl_mu.unlock(self.io);
        if (self.write_mu.tryLock()) {
            if (self.write_broken) {
                self.write_mu.unlock(self.io);
                return;
            }
            self.finishWriteAndUnlock(null, kill_on_err) catch {};
        }
    }

    /// Credits both the connection and the stream receive windows for `amt`
    /// bytes of consumed DATA. While the stream is still open, batches both
    /// windows at their half-window thresholds and coalesces any emitted frames
    /// into one flush; once the stream has ended (remote_closed/reset/gone),
    /// skips stream WINDOW_UPDATE and flushes all pending connection credit (#39).
    fn replenish(self: *Client, sid: u31, amt: u32) void {
        if (amt == 0) return;
        var stream_amt: u32 = 0;
        var stream_ended = true;
        self.streams_mu.lockUncancelable(self.io);
        if (self.streams.get(sid)) |s| {
            s.recv_mu.lockUncancelable(self.io);
            if (!s.remote_closed and s.reset == null and !s.cancelled and !s.goaway_refused) {
                stream_ended = false;
                s.recv_pending += @as(i64, amt);
                const iw: i64 = @intCast(p2.clampInitialWindow(self.cfg.initial_window_size));
                const threshold = @max(@as(i64, 1), iw >> 1);
                if (s.recv_pending >= threshold) {
                    const room: i64 = 0x7fff_ffff - s.recv_window;
                    const grant = @min(s.recv_pending, @max(@as(i64, 0), room));
                    if (grant > 0) {
                        s.recv_window += grant;
                        s.recv_pending -= grant;
                        stream_amt = @intCast(grant);
                    }
                }
            }
            s.recv_mu.unlock(self.io);
        }
        self.streams_mu.unlock(self.io);
        const conn_amt = self.creditConn(amt, stream_ended);
        self.writeWindowUpdates(conn_amt, sid, stream_amt);
    }

    fn handleWindowUpdate(self: *Client, sid: u31, payload: []const u8) !void {
        // RFC 9113 §5.1 / §6.9: WINDOW_UPDATE on an idle stream is a connection PROTOCOL_ERROR.
        if (sid != 0 and self.isIdleStream(sid)) {
            self.sendGoaway(.protocol_error);
            return error.ProtocolError;
        }
        // Length == 4 is guaranteed by proto.validateInboundFrame before dispatch.
        const incr: i64 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
        // A 0 increment is a PROTOCOL_ERROR: connection-level is fatal, stream
        // level resets just that stream (RFC 7540 §6.9).
        if (incr == 0) {
            if (sid == 0) {
                self.sendGoaway(.protocol_error);
                return error.ProtocolError;
            }
            self.streams_mu.lockUncancelable(self.io);
            if (self.streams.get(sid)) |st| {
                st.aborted.store(true, .release);
                st.recv_mu.lockUncancelable(self.io);
                if (st.reset == null) st.reset = @backingInt(p2.ErrorCode.protocol_error);
                st.recv_cond.broadcast(self.io);
                st.recv_mu.unlock(self.io);
                self.wakeStreamSender(st);
                self.noteEnd(st, true, true);
            }
            self.streams_mu.unlock(self.io);
            var p: [4]u8 = undefined;
            std.mem.writeInt(u32, &p, @backingInt(p2.ErrorCode.protocol_error), .big);
            self.writeFrame(.rst_stream, 0, sid, &p) catch {};
            return;
        }
        var conn_overflow = false;
        var overflow_sid: ?u31 = null;
        {
            self.streams_mu.lockUncancelable(self.io);
            defer self.streams_mu.unlock(self.io);
            var overflow_st: ?*Stream = null;
            {
                self.send_mu.lockUncancelable(self.io);
                defer self.send_mu.unlock(self.io);
                if (sid == 0) {
                    if (self.conn_send_window + incr > 0x7fff_ffff) {
                        conn_overflow = true;
                    } else {
                        self.conn_send_window += incr;
                        if (self.conn_send_window > 0) self.send_cond.broadcast(self.io);
                    }
                } else if (self.streams.get(sid)) |st| {
                    if (!st.aborted.load(.acquire)) {
                        if (st.send_window + incr > 0x7fff_ffff) {
                            // Stream overflow: close the stream locally and
                            // reset just that stream (RFC 7540 §6.9.1). Defer
                            // the RST_STREAM write until the locks drop.
                            st.send_window = 0;
                            st.aborted.store(true, .release);
                            overflow_st = st;
                            overflow_sid = sid;
                            self.wakeStreamSenderLocked(st);
                        } else {
                            st.send_window += incr;
                            if (st.send_window > 0) st.send_cond.broadcast(self.io);
                        }
                    }
                }
            }
            if (overflow_st) |st| {
                st.recv_mu.lockUncancelable(self.io);
                if (st.reset == null) st.reset = @backingInt(p2.ErrorCode.flow_control_error);
                st.recv_cond.broadcast(self.io);
                st.recv_mu.unlock(self.io);
                self.noteEnd(st, true, true);
            }
        }
        if (conn_overflow) {
            self.sendGoaway(.flow_control_error);
            return error.FlowControlError;
        }
        // Send the reset outside streams_mu/send_mu: writeFrame takes write_mu,
        // and openStream takes write_mu -> streams_mu, so holding streams_mu
        // across write_mu here would be a lock-order inversion (deadlock).
        if (overflow_sid) |osid| {
            var p: [4]u8 = undefined;
            std.mem.writeInt(u32, &p, @backingInt(p2.ErrorCode.flow_control_error), .big);
            self.writeFrame(.rst_stream, 0, osid, &p) catch {};
        }
    }

    fn applyPeerSettings(self: *Client, payload: []const u8) !?HtsUpdate {
        var i: usize = 0;
        var min_hts: ?u32 = null;
        var last_hts: ?u32 = null;
        while (i + 6 <= payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            switch (id) {
                p2.set_header_table_size => {
                    min_hts = if (min_hts) |m| @min(m, val) else val;
                    last_hts = val;
                },
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
                    // Apply immediately in wire order (RFC 9113 §6.5) so an
                    // intermediate overflow cannot be hidden by a later setting.
                    if (val > 0x7fff_ffff) {
                        self.sendGoaway(.flow_control_error);
                        return error.FlowControlError;
                    }
                    try self.applyInitialWindow(val);
                },
                p2.set_max_concurrent_streams => {
                    self.admit_mu.lockUncancelable(self.io);
                    self.peer_max_streams = val;
                    self.admit_cond.broadcast(self.io); // a raised limit wakes waiters
                    self.admit_mu.unlock(self.io);
                },
                p2.set_enable_push => {
                    // RFC 9113 §6.5.2 / §8.4: a server MUST NOT send ENABLE_PUSH=1,
                    // and values > 1 are invalid — either way PROTOCOL_ERROR.
                    if (val != 0) {
                        self.sendGoaway(.protocol_error);
                        return error.ProtocolError;
                    }
                },
                else => {},
            }
        }
        if (min_hts) |m| {
            self.peer_header_table_size = last_hts.?;
            return .{ .min = m, .last = last_hts.? };
        }
        return null;
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
                    if (s.*.aborted.load(.acquire)) continue;
                    // Each window is <= 2^31-1 and |delta| < 2^31, so the sum
                    // cannot overflow i64; a result over 2^31-1 is the illegal
                    // state itself.
                    s.*.send_window += delta;
                    if (s.*.send_window > 0x7fff_ffff) overflow = true;
                    if (delta > 0 and s.*.send_window > 0) s.*.send_cond.broadcast(self.io);
                }
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
            try self.readBytesBounded(&hb);
            const cf = p2.parseHeader(&hb);
            if (cf.ftype != .continuation or cf.sid != sid) {
                // A header block must not be interleaved with any other frame
                // (RFC 9113 §6.10) — a connection error, so say so on the wire
                // rather than just dropping the connection.
                self.sendGoaway(.protocol_error);
                return error.ProtocolError;
            }
            if (cf.length > self.maxRecvFrame()) {
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
            if (cf.length > 0) {
                try block.ensureUnusedCapacity(self.gpa, cf.length);
                const prev_len = block.items.len;
                const dst = block.addManyAsSliceAssumeCapacity(cf.length);
                self.readBytesBounded(dst) catch |err| {
                    block.items.len = prev_len;
                    return err;
                };
            }
            if (cf.flags & p2.flag_end_headers != 0) break;
        }
    }

    /// Background keepalive & teardown watcher raced alongside an in-flight
    /// `readVec` in `waitReadChunk`. Handles `setKeepalive()` reconfigurations
    /// and sends keepalive PING frames internally **without** returning and
    /// **without** cancelling the live `readVec` (protecting TLS record framing,
    /// #40). Only returns `.dead` once the connection is dead (`deinit`, `kill`,
    /// or keepalive timeout expiry), or `.canceled` when `readVec` completes.
    fn keepaliveAndStopWaiter(self: *Client, mid_frame: bool, initial_start_ns: i96) ReaderWake {
        var wait_start_ns = initial_start_ns;
        var prev_ka_time: u64 = self.keepalive_time_ms.load(.acquire);
        while (true) {
            var should_send_ping = false;
            var should_kill = false;
            {
                self.wake_mu.lockUncancelable(self.io);
                defer self.wake_mu.unlock(self.io);
                if (self.dead.load(.acquire)) return .dead;

                const seen_gen = self.ka_gen;
                const ka_time = self.keepalive_time_ms.load(.acquire);
                const ka_to = self.keepalive_timeout_ms.load(.acquire);
                if (ka_time == 0) {
                    prev_ka_time = 0;
                    // Drop any stale outstanding-PING state from before disable
                    // so re-enabling keepalive later starts a fresh idle window.
                    self.ping_outstanding.store(false, .release);
                    while (!self.dead.load(.acquire) and self.ka_gen == seen_gen) {
                        self.wake_cond.wait(self.io, &self.wake_mu) catch return .canceled;
                    }
                    if (self.dead.load(.acquire)) return .dead;
                    continue;
                }

                if (prev_ka_time == 0) {
                    // Keepalive was just enabled: anchor the window from now so a
                    // connection that sat idle with keepalive disabled is not killed.
                    wait_start_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
                }
                prev_ka_time = ka_time;

                const stall_ms = if (ka_to != 0) ka_to else ka_time;
                const waiting_reply = mid_frame or self.ping_outstanding.load(.acquire);
                const target_ms: u64 = if (waiting_reply) stall_ms else ka_time;
                const limit_ns: i96 = @as(i96, target_ms) * std.time.ns_per_ms;
                const now_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
                const elapsed_ns = now_ns - wait_start_ns;

                if (elapsed_ns < limit_ns) {
                    const rem_ns = limit_ns - elapsed_ns;
                    self.wake_cond.waitTimeout(self.io, &self.wake_mu, .{
                        .duration = .{ .raw = .{ .nanoseconds = rem_ns }, .clock = .awake },
                    }) catch |err| switch (err) {
                        error.Timeout => continue, // re-check deadline / handle spurious wakeups
                        error.Canceled => return .canceled,
                    };
                    if (self.dead.load(.acquire)) return .dead;
                    // Reconfigured via setKeepalive: adjust timer in place without cancelling readVec.
                    if (self.ka_gen != seen_gen and !mid_frame and !self.ping_outstanding.load(.acquire)) {
                        wait_start_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
                    }
                    continue;
                }

                if (waiting_reply) {
                    should_kill = true;
                } else {
                    // Arm `ping_outstanding` BEFORE flushing the PING onto the
                    // wire so neither an instant localhost PING(ACK) nor a
                    // concurrent `setKeepalive(0, 0)` can be overwritten when
                    // `writeFrame` returns.
                    self.ping_outstanding.store(true, .release);
                    should_send_ping = true;
                }
            }

            if (should_kill) {
                self.kill();
                return .dead;
            }
            if (should_send_ping) {
                if (self.dead.load(.acquire)) return .dead;
                const ping = @as([8]u8, @splat(0));
                self.writeFrame(.ping, 0, 0, &ping) catch {
                    self.kill();
                    return .dead;
                };
                wait_start_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
            }
        }
    }

    /// Reads `dst` incrementally while keepalive stall timeouts and teardown
    /// are handled by `keepaliveAndStopWaiter` without cancelling live reads (#40).
    fn readBytesBounded(self: *Client, dst: []u8) !void {
        var got: usize = 0;
        var last_progress_ns: i96 = Io.Timestamp.now(self.io, .awake).nanoseconds;
        while (got < dst.len) {
            const avail = self.r.buffered();
            if (avail.len > 0) {
                const take = @min(avail.len, dst.len - got);
                @memcpy(dst[got..][0..take], avail[0..take]);
                self.r.toss(take);
                got += take;
                self.ping_outstanding.store(false, .release);
                last_progress_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
                continue;
            }
            if (self.dead.load(.acquire)) return error.ConnectionClosed;
            const n = try self.waitReadChunk(dst[got..], true, last_progress_ns);
            if (n == 0) return error.EndOfStream;
            got += n;
            self.ping_outstanding.store(false, .release);
            last_progress_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
        }
        self.ping_outstanding.store(false, .release);
    }

    /// Reads the next 9-byte frame header without 50 ms polling or live-read
    /// cancellation (#40): `keepaliveAndStopWaiter` emits keepalive PINGs and
    /// tracks reconfiguration in place while `readVec` stays uninterrupted;
    /// `readVec` is only cancelled when the connection is already dead.
    fn readFrameHeader(self: *Client, hb: *[9]u8) !void {
        var got: usize = 0;
        var wait_start_ns: i96 = Io.Timestamp.now(self.io, .awake).nanoseconds;
        while (got < hb.len) {
            const avail = self.r.buffered();
            if (avail.len > 0) {
                const take = @min(avail.len, hb.len - got);
                @memcpy(hb[got..][0..take], avail[0..take]);
                self.r.toss(take);
                got += take;
                self.ping_outstanding.store(false, .release);
                wait_start_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
                continue;
            }
            if (self.dead.load(.acquire)) return error.ConnectionClosed;
            const n = try self.waitReadChunk(hb[got..], got > 0, wait_start_ns);
            if (n == 0) return error.EndOfStream;
            got += n;
            self.ping_outstanding.store(false, .release);
            wait_start_ns = Io.Timestamp.now(self.io, .awake).nanoseconds;
        }
        self.ping_outstanding.store(false, .release);
    }

    fn readChunkThunk(self: *Client, dst: []u8) anyerror!usize {
        var bufs = [_][]u8{dst};
        return self.r.readVec(&bufs);
    }

    fn waitReadChunk(self: *Client, dst: []u8, mid_frame: bool, wait_start_ns: i96) !usize {
        var buf: [2]ReadChunkOp = undefined;
        var sel = Io.Select(ReadChunkOp).init(self.io, &buf);
        // Spawn the watcher first so if concurrency is unavailable (or only one
        // slot is available and `.work` fails to spawn), `.work` is never
        // cancelled mid-flight and no read result/error is discarded.
        sel.concurrent(.wake, keepaliveAndStopWaiter, .{ self, mid_frame, wait_start_ns }) catch {
            var bufs = [_][]u8{dst};
            return self.r.readVec(&bufs);
        };
        sel.concurrent(.work, readChunkThunk, .{ self, dst }) catch {
            while (sel.cancel()) |_| {}
            var bufs = [_][]u8{dst};
            return self.r.readVec(&bufs);
        };
        const first = try sel.await();
        var got_n: ?usize = switch (first) {
            .work => |r| if (r) |n| n else |_| null,
            .wake => null,
        };
        var work_err: ?anyerror = switch (first) {
            .work => |r| if (r) |_| null else |e| e,
            .wake => null,
        };
        var wake_res: ?ReaderWake = switch (first) {
            .wake => |w| w,
            .work => null,
        };
        while (sel.cancel()) |leftover| switch (leftover) {
            .work => |r| if (r) |n| {
                got_n = n;
            } else |e| {
                if (work_err == null) work_err = e;
            },
            .wake => |w| {
                wake_res = w;
            },
        };
        // Priority: bytes actually read > real transport read error > dead signal.
        // `Io.Reader.readVec` wraps cancellation as `error.ReadFailed`, so treat
        // `work_err` as a real transport error only when `.work` won `await()` or
        // explicitly returned `EndOfStream` (which cancellation never produces).
        if (got_n) |n| return n;
        if (first == .work) return work_err orelse error.Canceled;
        if (work_err) |e| if (e == error.EndOfStream) return error.EndOfStream;
        if (wake_res == .dead) return error.ConnectionClosed;
        return work_err orelse error.Canceled;
    }
};

/// RFC 9113 §8.1 / §8.1.1 / §8.2 / §8.3.2 response HEADERS & trailers validator.
fn validateStreamHeaders(s: *Stream, hs: []const Header, end_stream: bool) bool {
    switch (s.resp_phase) {
        .expect_headers => {
            var saw_regular = false;
            var status_val: ?u16 = null;
            var cl: ?u64 = null;
            for (hs) |h| {
                if (h.name.len == 0 or !p2.isValidFieldValue(h.value)) return false;
                if (h.name[0] == ':') {
                    if (saw_regular) return false;
                    if (!std.mem.eql(u8, h.name, ":status")) return false;
                    if (status_val != null or h.value.len != 3) return false;
                    if (!std.ascii.isDigit(h.value[0]) or !std.ascii.isDigit(h.value[1]) or !std.ascii.isDigit(h.value[2])) return false;
                    const code = std.fmt.parseInt(u16, h.value, 10) catch return false;
                    if (code < 100 or code > 599 or code == 101) return false;
                    status_val = code;
                    continue;
                }
                saw_regular = true;
                if (!p2.isValidFieldName(h.name)) return false;
                if (p2.isConnectionSpecificHeader(h.name)) return false;
                // RFC 9113 §8.2.2: `te` is only permitted in HTTP/2 requests.
                if (std.mem.eql(u8, h.name, "te")) return false;
                if (std.mem.eql(u8, h.name, "content-length")) {
                    const parsed = p2.parseContentLength(h.value) orelse return false;
                    if (cl) |first| {
                        if (first != parsed) return false;
                    } else {
                        cl = parsed;
                    }
                }
            }
            const status = status_val orelse return false;
            if (status < 200) {
                if (end_stream) return false; // 1xx informational cannot end the stream
                return true;
            }
            // RFC 9113 §8.1.1: 204, 304, and responses to HEAD MAY carry a
            // non-zero content-length header even though no DATA payload follows.
            if (s.is_head_request or status == 204 or status == 304) {
                s.resp_content_length = 0;
            } else {
                if (end_stream and cl != null and cl.? != 0) return false;
                s.resp_content_length = cl;
            }
            s.resp_phase = .expect_body_or_trailers;
            return true;
        },
        .expect_body_or_trailers => {
            if (!end_stream) return false;
            for (hs) |h| {
                // RFC 9113 §8.2.2: connection-specific headers and `te` are forbidden in trailers.
                if (!p2.isValidFieldName(h.name) or !p2.isValidFieldValue(h.value) or
                    p2.isConnectionSpecificHeader(h.name) or std.mem.eql(u8, h.name, "te"))
                {
                    return false;
                }
            }
            if (s.resp_content_length) |cl| {
                if (s.rx_body_bytes != cl) return false;
            }
            return true;
        },
    }
}

fn freeHeaders(gpa: std.mem.Allocator, hs: []const Header) void {
    hpack.freeHeaders(gpa, hs);
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
    std.mem.writeInt(u32, &rst, @backingInt(p2.ErrorCode.cancel), .big);
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
    // Pin to the RFC floor so handshake emits no startup stream-0 WINDOW_UPDATE
    // and half-window batching triggers on 32768+ consumed bytes.
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = @intCast(p2.default_window),
        .initial_window_size = @intCast(p2.default_window),
    });
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [70000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    var pf: [p2.preface.len]u8 = undefined;
    try asr.interface.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, &asr.interface);
    cs.deinit(testing.allocator);
    try ctWrite(&asw.interface, .settings, 0, 0, "");
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    const s = try client.openStream(.{ .path = "/x" }, true);

    // Response: HEADERS(:status 200), 3 × 12000 B DATA (36000 B > 32767 half-window
    // threshold), then a PING. The client processes frames in order, so any
    // WINDOW_UPDATE emitted before consumption arrives before the PING ack.
    var henc = std.heap.ArenaAllocator.init(testing.allocator);
    defer henc.deinit();
    var blk: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(henc.allocator(), &blk, 200, &.{});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, blk.items);
    var chunk: [12000]u8 = @splat('h');
    for (0..3) |_| try ctWrite(&asw.interface, .data, 0, 1, &chunk);
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

    // Consume the 3 DATA frames (36000 B); crossing the half-window threshold
    // must emit batched WINDOW_UPDATEs totaling 36000 bytes for both windows.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e1 = try s.readEvent(arena.allocator());
    try testing.expect(e1 == .headers);
    for (0..3) |_| {
        const e = try s.readEvent(arena.allocator());
        try testing.expectEqual(@as(usize, chunk.len), e.data.payload.len);
    }

    var conn_credited: u32 = 0;
    var stream_credited: u32 = 0;
    while (conn_credited < 36000 or stream_credited < 36000) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update) {
            const incr = std.mem.readInt(u32, f.payload[0..4], .big);
            if (f.hdr.sid == 0) conn_credited += incr else if (f.hdr.sid == 1) stream_credited += incr;
        }
    }
    try testing.expectEqual(@as(u32, 36000), conn_credited);
    try testing.expectEqual(@as(u32, 36000), stream_credited);
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
    std.mem.writeInt(u32, ga[4..8], @backingInt(p2.ErrorCode.no_error), .big);
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
    std.mem.writeInt(u32, &rst, @backingInt(p2.ErrorCode.cancel), .big);
    try ctWrite(&asw.interface, .rst_stream, 0, 1, &rst);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e1 = try s.readEvent(arena.allocator());
    try testing.expect(e1 == .rst);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.cancel)), e1.rst.code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.frame_size_error)), code);

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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.enhance_your_calm)), code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.frame_size_error)), code);
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
    client.setKeepalive(100, 100);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.enhance_your_calm)), code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), code);
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
    try ctHandshakeEx(asr, asw, true);
}

fn ctHandshakeFloor(asr: *Io.Reader, asw: *Io.Writer) !void {
    try ctHandshakeEx(asr, asw, false);
}

fn ctHandshakeEx(asr: *Io.Reader, asw: *Io.Writer, expect_conn_wu: bool) !void {
    var pf: [p2.preface.len]u8 = undefined;
    try asr.readSliceAll(&pf);
    var cs = try ctRead(testing.allocator, asr); // client SETTINGS
    cs.deinit(testing.allocator);
    if (expect_conn_wu) {
        var wu = try ctRead(testing.allocator, asr); // default 1 MiB stream-0 WINDOW_UPDATE
        defer wu.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.window_update, wu.hdr.ftype);
        try testing.expectEqual(@as(u31, 0), wu.hdr.sid);
    }
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.frame_size_error)), code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.frame_size_error)), code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.frame_size_error)), code);
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), code);
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
            try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), std.mem.readInt(u32, f.payload[0..4], .big));
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.flow_control_error)), code);

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
    // Pinned to the RFC floor so 4 × 16384 = 65536 crosses the 65535 window.
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = @intCast(p2.default_window),
        .initial_window_size = @intCast(p2.default_window),
    });

    var arbuf: [8192]u8 = undefined;
    var awbuf: [70000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshakeFloor(&asr.interface, &asw.interface);

    _ = try client.openStream(.{ .path = "/x" }, false);
    const resp_200 = [_]u8{0x88};
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, &resp_200);
    var big: [16384]u8 = @splat('x');
    // 16384 * 4 = 65536 > the 65535-byte connection window: the fourth frame
    // crosses it. Previously all of it was buffered without bound.
    try ctWrite(&asw.interface, .data, 0, 1, &big);
    try ctWrite(&asw.interface, .data, 0, 1, &big);
    try ctWrite(&asw.interface, .data, 0, 1, &big);
    try ctWrite(&asw.interface, .data, 0, 1, &big);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.flow_control_error)), code);
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
    // Pin to the RFC floor so 4 × 16 KiB requires replenishment after the first 3 frames.
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = @intCast(p2.default_window),
        .initial_window_size = @intCast(p2.default_window),
    });
    defer client.deinit();

    var arbuf: [8192]u8 = undefined;
    var awbuf: [70000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshakeFloor(&asr.interface, &asw.interface);

    const s = try client.openStream(.{ .path = "/x" }, false);
    const resp_200 = [_]u8{0x88};
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, &resp_200);
    var chunk: [16384]u8 = @splat('y');
    try ctWrite(&asw.interface, .data, 0, 1, &chunk);
    try ctWrite(&asw.interface, .data, 0, 1, &chunk);
    try ctWrite(&asw.interface, .data, 0, 1, &chunk);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ev0 = try s.readEvent(arena);
    try testing.expect(ev0 == .headers);
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const ev = try s.readEvent(arena);
        try testing.expectEqual(@as(usize, 16384), ev.data.payload.len);
    }

    // Batched replenishment emits one stream WINDOW_UPDATE (>= 32768 B) once
    // half of the 65535-byte window is consumed, making the 4th frame legal.
    var credited_stream: u32 = 0;
    while (credited_stream < 16384) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update and f.hdr.sid == 1) {
            credited_stream += std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
        }
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), code);
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
            std.mem.readInt(u32, f.payload[0..4], .big) == @backingInt(p2.ErrorCode.stream_closed))
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
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), code);
    client.deinit();
}

test "client survives a frame header split across a >reader_wake_ms gap (#15)" {
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
    var ack = try ctRead(testing.allocator, &asr.interface);
    ack.deinit(testing.allocator);

    const s = try client.openStream(.{ .path = "/x" }, true);
    defer s.close();
    var req = try ctRead(testing.allocator, &asr.interface);
    req.deinit(testing.allocator);

    // HEADERS (:status 200) whose 9-byte header is split 4 + 5 across 150 ms (> 50 ms wake).
    const resp = [_]u8{ 0x08, 0x03, '2', '0', '0' };
    var hdr_frame: [9 + resp.len]u8 = undefined;
    p2.putHeader(hdr_frame[0..9], resp.len, .headers, p2.flag_end_headers, 1);
    @memcpy(hdr_frame[9..], &resp);
    try asw.interface.writeAll(hdr_frame[0..4]);
    try asw.interface.flush();
    Io.sleep(io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .awake) catch {};
    try asw.interface.writeAll(hdr_frame[4..]);
    try asw.interface.flush();

    // Follow with a DATA frame whose header is split 8 + 1 across 150 ms.
    const body = "hello";
    var data_frame: [9 + body.len]u8 = undefined;
    p2.putHeader(data_frame[0..9], body.len, .data, p2.flag_end_stream, 1);
    @memcpy(data_frame[9..], body);
    try asw.interface.writeAll(data_frame[0..8]);
    try asw.interface.flush();
    Io.sleep(io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .awake) catch {};
    try asw.interface.writeAll(data_frame[8..]);
    try asw.interface.flush();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ev1 = try s.readEvent(arena.allocator());
    try testing.expect(ev1 == .headers);
    try testing.expect(!ev1.headers.end_stream);
    const ev2 = try s.readEvent(arena.allocator());
    try testing.expect(ev2 == .data);
    try testing.expect(ev2.data.end_stream);
    try testing.expectEqualStrings(body, ev2.data.payload);
    try testing.expect(!client.dead.load(.acquire));
}

test "client with keepalive does not drop or PING mid-header (#15)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    var accepted = try srv.accept(io);
    defer accepted.close(io);

    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    client.setKeepalive(80, 500);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);
    var ack = try ctRead(testing.allocator, &asr.interface);
    ack.deinit(testing.allocator);

    const s = try client.openStream(.{ .path = "/ka" }, true);
    var req = try ctRead(testing.allocator, &asr.interface);
    req.deinit(testing.allocator);

    // Split the response header across 200 ms (> keepalive_time_ms, < keepalive_timeout_ms).
    const resp = [_]u8{ 0x08, 0x03, '2', '0', '0' };
    var hdr_frame: [9 + resp.len]u8 = undefined;
    p2.putHeader(hdr_frame[0..9], resp.len, .headers, p2.flag_end_headers | p2.flag_end_stream, 1);
    @memcpy(hdr_frame[9..], &resp);
    try asw.interface.writeAll(hdr_frame[0..4]);
    try asw.interface.flush();
    Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .awake) catch {};
    try asw.interface.writeAll(hdr_frame[4..]);
    try asw.interface.flush();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ev = try s.readEvent(arena.allocator());
    try testing.expect(ev == .headers);
    try testing.expect(ev.headers.end_stream);
    try testing.expect(!client.dead.load(.acquire));

    // Tear down cleanly and verify the client emitted no spurious PING or GOAWAY
    // while the frame header was in flight.
    s.close();
    client.deinit();
    cstream.close(io);
    try testing.expectError(error.EndOfStream, ctRead(testing.allocator, &asr.interface));
}

test "client with keepalive kills a peer that stalls mid-header (#15)" {
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
    client.setKeepalive(5_000, 120);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);
    var ack = try ctRead(testing.allocator, &asr.interface);
    ack.deinit(testing.allocator);

    const s = try client.openStream(.{ .path = "/stall" }, true);
    defer s.close();
    var req = try ctRead(testing.allocator, &asr.interface);
    req.deinit(testing.allocator);

    // Deliver 4 bytes of a frame header and stall forever: keepalive_timeout_ms
    // must still declare the peer dead instead of spinning indefinitely.
    var partial: [9]u8 = undefined;
    p2.putHeader(&partial, 5, .headers, p2.flag_end_headers | p2.flag_end_stream, 1);
    try asw.interface.writeAll(partial[0..4]);
    try asw.interface.flush();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const start = Io.Timestamp.now(io, .awake).nanoseconds;
    try testing.expectError(error.ConnectionClosed, s.readEvent(arena.allocator()));
    const elapsed_ms = @divFloor(Io.Timestamp.now(io, .awake).nanoseconds - start, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 2_000);
}

const CancelRaceCtx = struct {
    stop: std.atomic.Value(bool) = .init(false),
    seq: std.atomic.Value(u32) = .init(0),
    send_done: std.atomic.Value(u32) = .init(0),
    cur: *Stream = undefined,
};

fn cancelRaceSender(ctx: *CancelRaceCtx) void {
    const payload = @as([50]u8, @splat('x'));
    var last: u32 = 0;
    while (!ctx.stop.load(.acquire)) {
        const seq = ctx.seq.load(.acquire);
        if (seq == last) {
            std.atomic.spinLoopHint();
            continue;
        }
        last = seq;
        _ = ctx.cur.send(&payload, false) catch {};
        ctx.send_done.store(seq, .release);
    }
}

fn cancelRaceDrain(r: *Io.Reader, stop: *std.atomic.Value(bool)) void {
    var tmp: [65536]u8 = undefined;
    while (!stop.load(.acquire)) {
        _ = r.readSliceShort(&tmp) catch return;
    }
}

test "cancel() never loses a wake-up against a send() entering the window wait (#18)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    var accepted = try srv.accept(io);

    var crbuf: [65536]u8 = undefined;
    var cwbuf: [65536]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    var torn = false;
    defer if (!torn) {
        client.deinit();
        accepted.close(io);
        cstream.close(io);
    };

    var arbuf: [65536]u8 = undefined;
    var awbuf: [65536]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);
    var ack1 = try ctRead(testing.allocator, &asr.interface);
    ack1.deinit(testing.allocator);

    // Zero initial stream window so every send() enters the send_cond wait.
    var iw: [6]u8 = undefined;
    p2.putSetting(&iw, p2.set_initial_window_size, 0);
    try ctWrite(&asw.interface, .settings, 0, 0, &iw);
    var ack2 = try ctRead(testing.allocator, &asr.interface);
    ack2.deinit(testing.allocator);

    var drain_stop = std.atomic.Value(bool).init(false);
    const drain_th = try std.Thread.spawn(.{}, cancelRaceDrain, .{ &asr.interface, &drain_stop });
    var ctx: CancelRaceCtx = .{};
    const sender_th = try std.Thread.spawn(.{}, cancelRaceSender, .{&ctx});

    var rng: u64 = 0x9e3779b97f4a7c15;
    const rounds: u32 = 2_000;
    var stuck: u32 = 0;
    var seq: u32 = 0;
    while (seq < rounds) : (seq += 1) {
        const s = try client.openStream(.{ .path = "/s" }, false);
        ctx.cur = s;
        ctx.seq.store(seq + 1, .release);
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        var spin: u32 = @intCast(rng % 2000);
        while (spin > 0) : (spin -= 1) std.atomic.spinLoopHint();
        try s.cancel();

        var waited: u32 = 0;
        while (ctx.send_done.load(.acquire) != seq + 1 and waited < 50) : (waited += 1) {
            Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms }, .awake) catch {};
        }
        if (ctx.send_done.load(.acquire) != seq + 1) {
            stuck += 1;
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, 65535, .big);
            try ctWrite(&asw.interface, .window_update, 0, s.id, &wu);
            waited = 0;
            while (ctx.send_done.load(.acquire) != seq + 1 and waited < 200) : (waited += 1) {
                Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms }, .awake) catch {};
            }
        }
        s.close();
    }

    ctx.stop.store(true, .release);
    sender_th.join();
    drain_stop.store(true, .release);
    client.deinit();
    cstream.close(io);
    drain_th.join();
    accepted.close(io);
    torn = true;
    try testing.expectEqual(@as(u32, 0), stuck);
}

test "stream WINDOW_UPDATE overflow closes the stream locally (#19)" {
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
    var ack1 = try ctRead(testing.allocator, &asr.interface);
    ack1.deinit(testing.allocator);

    // Limit to 1 concurrent stream to verify the overflow releases the slot.
    var mcs: [6]u8 = undefined;
    p2.putSetting(&mcs, p2.set_max_concurrent_streams, 1);
    try ctWrite(&asw.interface, .settings, 0, 0, &mcs);
    var ack2 = try ctRead(testing.allocator, &asr.interface);
    ack2.deinit(testing.allocator);

    const s = try client.openStream(.{ .path = "/x" }, false);
    defer s.close();
    var req1 = try ctRead(testing.allocator, &asr.interface);
    req1.deinit(testing.allocator);

    // 65535 + (2^31 - 1) overflows stream 1's send window.
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, 0x7fff_ffff, .big);
    try ctWrite(&asw.interface, .window_update, 0, 1, &wu);

    var rst = try ctRead(testing.allocator, &asr.interface);
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.rst_stream, rst.hdr.ftype);
    try testing.expectEqual(@as(u31, 1), rst.hdr.sid);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.flow_control_error)), std.mem.readInt(u32, rst.payload[0..4], .big));

    // 1. send() fails immediately with StreamReset instead of blocking on a 0 window.
    try testing.expectError(error.StreamReset, s.send("hello", false));
    try testing.expectError(error.StreamReset, s.send("", true));

    // 2. A later WINDOW_UPDATE must not revive the reset stream.
    std.mem.writeInt(u32, &wu, 1000, .big);
    try ctWrite(&asw.interface, .window_update, 0, 1, &wu);
    // 3. A later HEADERS on the reset stream must not surface as a live .headers event.
    const resp = [_]u8{ 0x08, 0x03, '2', '0', '0' };
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 1, &resp);
    // Sync with the reader via a PING/ACK so both frames above have been processed.
    const ping = @as([8]u8, @splat(0x42));
    try ctWrite(&asw.interface, .ping, 0, 0, &ping);
    var pong = try ctRead(testing.allocator, &asr.interface);
    defer pong.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.ping, pong.hdr.ftype);

    try testing.expectError(error.StreamReset, s.send("more", false));
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ev = try s.readEvent(arena.allocator());
    try testing.expect(ev == .rst);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.flow_control_error)), ev.rst.code);
    try testing.expectError(error.EndOfStream, s.readEvent(arena.allocator()));

    // 4. Admission slot was freed (MAX_CONCURRENT_STREAMS = 1), so a new stream opens immediately.
    const s3 = try client.openStream(.{ .path = "/y" }, true);
    defer s3.close();
    var req3 = try ctRead(testing.allocator, &asr.interface);
    defer req3.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.headers, req3.hdr.ftype);
    try testing.expectEqual(@as(u31, 3), req3.hdr.sid);
    try testing.expect(!client.dead.load(.acquire));
}

test "Stream.readEvent does not leak gpa memory or conn window on arena OOM (#23)" {
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

    const s = try client.openStream(.{ .path = "/oom" }, true);
    defer s.close();
    var req = try ctRead(testing.allocator, &asr.interface);
    req.deinit(testing.allocator);

    const resp = [_]u8{0x88}; // :status 200
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, &resp);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, 1, "payload");

    // First attempt with a failing allocator fails with OutOfMemory, keeping
    // the queued items intact (no gpa leak, no lost fc_cost).
    var fail_alloc = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, s.readEvent(fail_alloc.allocator()));

    // Retry with a real arena succeeds and delivers both HEADERS and DATA.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ev1 = try s.readEvent(arena.allocator());
    try testing.expect(ev1 == .headers);
    try testing.expectError(error.OutOfMemory, s.readEvent(fail_alloc.allocator()));
    const ev2 = try s.readEvent(arena.allocator());
    try testing.expect(ev2 == .data);
    try testing.expectEqualStrings("payload", ev2.data.payload);
    try testing.expect(ev2.data.end_stream);
}

test "client keepalive with timeout_ms=0 falls back to time_ms and stays alive on PING ACK (#23)" {
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
    try ctHandshake(&asr.interface, &asw.interface);

    // timeout_ms=0 must fall back to time_ms (80ms), not sleep 0ms and kill immediately.
    client.setKeepalive(80, 0);
    var ping: CtFrame = undefined;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        if (f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0)) {
            f.deinit(testing.allocator);
            continue;
        }
        ping = f;
        break;
    }
    defer ping.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.ping, ping.hdr.ftype);
    Io.sleep(io, .{ .nanoseconds = 30 * std.time.ns_per_ms }, .awake) catch {};
    try ctWrite(&asw.interface, .ping, p2.flag_ack, 0, ping.payload);
    Io.sleep(io, .{ .nanoseconds = 40 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(!client.dead.load(.acquire));
}

test "client handles multiple GOAWAY frames safely with non-increasing last_stream_id (#23)" {
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

    const s1 = try client.openStream(.{ .path = "/1" }, true);
    defer s1.close();
    const s3 = try client.openStream(.{ .path = "/3" }, true);
    defer s3.close();
    var r1 = try ctRead(testing.allocator, &asr.interface);
    r1.deinit(testing.allocator);
    var r3 = try ctRead(testing.allocator, &asr.interface);
    r3.deinit(testing.allocator);

    // First GOAWAY(2^31-1, NO_ERROR), then second GOAWAY(1, NO_ERROR).
    var ga: [8]u8 = undefined;
    std.mem.writeInt(u32, ga[0..4], 0x7fff_ffff, .big);
    std.mem.writeInt(u32, ga[4..8], @backingInt(p2.ErrorCode.no_error), .big);
    try ctWrite(&asw.interface, .goaway, 0, 0, &ga);
    std.mem.writeInt(u32, ga[0..4], 1, .big);
    try ctWrite(&asw.interface, .goaway, 0, 0, &ga);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ev3 = try s3.readEvent(arena.allocator());
    try testing.expect(ev3 == .goaway);
    const g = client.goAway().?;
    try testing.expectEqual(@as(u31, 1), g.last_stream_id);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.no_error)), g.code);
}

test "Stream.close on half-closed(remote) stream sends RST_STREAM(CANCEL) (#23)" {
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

    // Client opens stream WITHOUT END_STREAM (local half still open).
    const s = try client.openStream(.{ .path = "/bidi" }, false);
    var req = try ctRead(testing.allocator, &asr.interface);
    req.deinit(testing.allocator);

    // Server sends HEADERS(END_STREAM) -> stream is half-closed (remote).
    const resp = [_]u8{0x88};
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 1, &resp);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ev = try s.readEvent(arena.allocator());
    try testing.expect(ev == .headers and ev.headers.end_stream);

    // Closing must send RST_STREAM(CANCEL) so the server stops waiting for body.
    s.close();
    var rst: CtFrame = undefined;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        if (f.hdr.ftype == .rst_stream) {
            rst = f;
            break;
        }
        f.deinit(testing.allocator);
    }
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.rst_stream, rst.hdr.ftype);
    try testing.expectEqual(@as(u31, 1), rst.hdr.sid);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.cancel)), std.mem.readInt(u32, rst.payload[0..4], .big));
}

test "client rejects DATA after END_STREAM with STREAM_CLOSED (#23)" {
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

    // Stream 1: half-closed (remote) -> extra DATA triggers RST_STREAM(STREAM_CLOSED).
    const s1 = try client.openStream(.{ .path = "/half" }, false);
    defer s1.close();
    const resp = [_]u8{0x88};
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 1, &resp);
    try ctWrite(&asw.interface, .data, 0, 1, "junk");

    var rst: CtFrame = undefined;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        if (f.hdr.ftype == .rst_stream) {
            rst = f;
            break;
        }
        f.deinit(testing.allocator);
    }
    defer rst.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.rst_stream, rst.hdr.ftype);
    try testing.expectEqual(@as(u31, 1), rst.hdr.sid);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.stream_closed)), std.mem.readInt(u32, rst.payload[0..4], .big));

    // Stream 3: fully closed (local END_STREAM + remote END_STREAM) -> extra DATA triggers GOAWAY(STREAM_CLOSED).
    const s3 = try client.openStream(.{ .path = "/full" }, true);
    defer s3.close();
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 3, &resp);
    try ctWrite(&asw.interface, .data, 0, 3, "junk");

    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.stream_closed)), code);
}

test "client rejects bad preface, ENABLE_PUSH=1, idle RST/WU/DATA/HEADERS, and bad HPACK (#23)" {
    const io = testing.io;
    const Case = enum { bad_preface, enable_push, idle_rst, idle_wu, even_data, idle_headers, bad_hpack };
    const cases = [_]struct { c: Case, want: p2.ErrorCode }{
        .{ .c = .bad_preface, .want = .protocol_error },
        .{ .c = .enable_push, .want = .protocol_error },
        .{ .c = .idle_rst, .want = .protocol_error },
        .{ .c = .idle_wu, .want = .protocol_error },
        .{ .c = .even_data, .want = .protocol_error },
        .{ .c = .idle_headers, .want = .protocol_error },
        .{ .c = .bad_hpack, .want = .compression_error },
    };

    for (cases) |tc| {
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

        if (tc.c == .bad_preface) {
            var pf: [p2.preface.len]u8 = undefined;
            try asr.interface.readSliceAll(&pf);
            var cs = try ctRead(testing.allocator, &asr.interface);
            cs.deinit(testing.allocator);
            const ping = @as([8]u8, @splat(0));
            try ctWrite(&asw.interface, .ping, 0, 0, &ping);
        } else if (tc.c == .enable_push) {
            var pf: [p2.preface.len]u8 = undefined;
            try asr.interface.readSliceAll(&pf);
            var cs = try ctRead(testing.allocator, &asr.interface);
            cs.deinit(testing.allocator);
            var sbuf: [6]u8 = undefined;
            p2.putSetting(&sbuf, p2.set_enable_push, 1);
            try ctWrite(&asw.interface, .settings, 0, 0, &sbuf);
        } else {
            try ctHandshake(&asr.interface, &asw.interface);
            switch (tc.c) {
                .idle_rst => {
                    var rst: [4]u8 = undefined;
                    std.mem.writeInt(u32, &rst, @backingInt(p2.ErrorCode.cancel), .big);
                    try ctWrite(&asw.interface, .rst_stream, 0, 99, &rst);
                },
                .idle_wu => {
                    var wu: [4]u8 = undefined;
                    std.mem.writeInt(u32, &wu, 100, .big);
                    try ctWrite(&asw.interface, .window_update, 0, 99, &wu);
                },
                .even_data => {
                    const s = try client.openStream(.{ .path = "/x" }, true);
                    defer s.close();
                    var r = try ctRead(testing.allocator, &asr.interface);
                    r.deinit(testing.allocator);
                    try ctWrite(&asw.interface, .data, 0, 2, "x");
                },
                .idle_headers => {
                    const resp = [_]u8{0x88};
                    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 2, &resp);
                },
                .bad_hpack => {
                    const s = try client.openStream(.{ .path = "/x" }, true);
                    defer s.close();
                    var r = try ctRead(testing.allocator, &asr.interface);
                    r.deinit(testing.allocator);
                    const bad = [_]u8{ 0x88, 0x20 }; // mid-block dynamic table size update
                    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 1, &bad);
                },
                else => unreachable,
            }
        }

        const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
        try testing.expectEqual(@as(u32, @backingInt(tc.want)), code);
        try waitDead(io, &client, 3000);
    }
}

test "deinit waits for an in-flight openStream blocked on MAX_CONCURRENT_STREAMS (no UAF)" {
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
    var st_max: [6]u8 = undefined;
    p2.putSetting(&st_max, p2.set_max_concurrent_streams, 0);
    try ctWrite(&asw.interface, .settings, 0, 0, &st_max);
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");
    // Wait until client processes SETTINGS(MAX_CONCURRENT_STREAMS=0), skipping
    // the startup stream-0 WINDOW_UPDATE frame.
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    var ctx: OpenCtx = .{ .client = &client };
    const opener = try std.Thread.spawn(.{}, openThread, .{&ctx});
    Io.sleep(io, .{ .nanoseconds = 40 * std.time.ns_per_ms }, .awake) catch {};

    client.deinit();
    opener.join();
    try testing.expect(!ctx.ok);
    try testing.expectEqual(@as(?anyerror, error.ConnectionClosed), ctx.err);
}

test "client emits HPACK dynamic table size update (0) after peer SETTINGS_HEADER_TABLE_SIZE=0" {
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

    var st_zero: [6]u8 = undefined;
    p2.putSetting(&st_zero, p2.set_header_table_size, 0);
    try ctWrite(&asw.interface, .settings, 0, 0, &st_zero);
    try ctWrite(&asw.interface, .settings, p2.flag_ack, 0, "");

    // Wait for client's SETTINGS(ACK).
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    const s = try client.openStream(.{ .path = "/hpack" }, true);
    defer s.close();
    var req_frame = try ctRead(testing.allocator, &asr.interface);
    defer req_frame.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.headers, req_frame.hdr.ftype);
    try testing.expect(req_frame.payload.len > 0);
    try testing.expectEqual(@as(u8, 0x20), req_frame.payload[0]);

    var dec = hpack.Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    _ = try dec.decode(arena_state.allocator(), req_frame.payload);
    try testing.expectEqual(@as(usize, 0), dec.dyn.max_size);
}

test "client validates response framing, :status, field syntax, 1xx, and Content-Length" {
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

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 1. DATA before initial HEADERS -> RST_STREAM(PROTOCOL_ERROR)
    const s1 = try client.openStream(.{ .path = "/data-first" }, true);
    defer s1.close();
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, 1, "oops");
    const ev1 = try s1.readEvent(arena);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), ev1.rst.code);

    // 2. :status 101 Switching Protocols -> RST_STREAM(PROTOCOL_ERROR) (RFC 9113 §8.3.2)
    const s3 = try client.openStream(.{ .path = "/101" }, true);
    defer s3.close();
    var b101: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(arena, &b101, 101, &.{});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 3, b101.items);
    const ev3 = try s3.readEvent(arena);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), ev3.rst.code);

    // 3. Content-Length mismatch (advertises 5, sends 3 + END_STREAM) -> RST_STREAM(PROTOCOL_ERROR)
    const s5 = try client.openStream(.{ .path = "/cl" }, true);
    defer s5.close();
    var bcl: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(arena, &bcl, 200, &.{.{ .name = "content-length", .value = "5" }});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 5, bcl.items);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, 5, "abc");
    _ = try s5.readEvent(arena); // .headers
    const ev5 = try s5.readEvent(arena);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), ev5.rst.code);

    // 4. Valid 100 Continue (no END_STREAM) followed by 200 OK + matching body succeeds.
    const s7 = try client.openStream(.{ .path = "/100" }, true);
    defer s7.close();
    var b100: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(arena, &b100, 100, &.{});
    var b200: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(arena, &b200, 200, &.{.{ .name = "content-length", .value = "2" }});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 7, b100.items);
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 7, b200.items);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, 7, "ok");
    const e7_1 = try s7.readEvent(arena);
    try testing.expect(e7_1 == .headers);
    const e7_2 = try s7.readEvent(arena);
    try testing.expect(e7_2 == .headers);
    const e7_3 = try s7.readEvent(arena);
    try testing.expectEqualStrings("ok", e7_3.data.payload);

    // 5. 204 No Content + non-zero content-length with END_STREAM is allowed (RFC 9113 §8.1.1),
    // while 204 followed by non-empty DATA is rejected with RST_STREAM(PROTOCOL_ERROR).
    const s9 = try client.openStream(.{ .path = "/204-ok" }, true);
    defer s9.close();
    var b204: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeResponse(arena, &b204, 204, &.{.{ .name = "content-length", .value = "5" }});
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, 9, b204.items);
    const e9 = try s9.readEvent(arena);
    try testing.expect(e9 == .headers and e9.headers.end_stream);

    const s11 = try client.openStream(.{ .path = "/204-bad-data" }, true);
    defer s11.close();
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 11, b204.items);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, 11, "x");
    _ = try s11.readEvent(arena); // .headers
    const e11 = try s11.readEvent(arena);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), e11.rst.code);
    try testing.expect(!client.dead.load(.acquire));
}

test "replenish skips stream WINDOW_UPDATE after END_STREAM and send rejects post-END_STREAM writes" {
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
    // Pin to the RFC floor so 3 × 12000 = 36000 B crosses the half-window
    // connection replenishment threshold while still verifying stream WU is skipped.
    try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
        .connection_window_size = @intCast(p2.default_window),
        .initial_window_size = @intCast(p2.default_window),
    });
    defer client.deinit();

    var arbuf: [4096]u8 = undefined;
    var awbuf: [70000]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshakeFloor(&asr.interface, &asw.interface);
    var ack = try ctRead(testing.allocator, &asr.interface);
    ack.deinit(testing.allocator);

    const s = try client.openStream(.{ .method = "POST", .path = "/up" }, false);
    defer s.close();
    var req = try ctRead(testing.allocator, &asr.interface);
    req.deinit(testing.allocator);

    try s.send("done", true);
    var d1 = try ctRead(testing.allocator, &asr.interface);
    d1.deinit(testing.allocator);
    try testing.expectError(error.StreamClosed, s.send("extra", false));
    try testing.expectError(error.StreamClosed, s.send("", true));

    // Peer sends 200 OK + 36000 B across 3 DATA frames (END_STREAM on last);
    // consuming all DATA crosses the half-window threshold and must emit conn
    // WINDOW_UPDATE(0) ONLY (no stream WINDOW_UPDATE on sid 1), followed by PING.
    const resp = [_]u8{0x88};
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, &resp);
    var reply_chunk: [12000]u8 = @splat('r');
    try ctWrite(&asw.interface, .data, 0, 1, &reply_chunk);
    try ctWrite(&asw.interface, .data, 0, 1, &reply_chunk);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, 1, &reply_chunk);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    _ = try s.readEvent(arena_state.allocator());
    for (0..3) |_| _ = try s.readEvent(arena_state.allocator());

    const ping: [8]u8 = @splat(0x42);
    try ctWrite(&asw.interface, .ping, 0, 0, &ping);

    var saw_conn_wu = false;
    var saw_stream_wu = false;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update) {
            if (f.hdr.sid == 0) saw_conn_wu = true else saw_stream_wu = true;
        }
        if (f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack != 0)) break;
    }
    try testing.expect(saw_conn_wu);
    try testing.expect(!saw_stream_wu);
}

test "keepalive bounds mid-payload stall and deinit wakes promptly under long keepalive" {
    const io = testing.io;
    {
        // Part A: mid-payload stall is killed by keepalive_timeout_ms.
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
        client.setKeepalive(5_000, 120);

        var arbuf: [4096]u8 = undefined;
        var awbuf: [4096]u8 = undefined;
        var asr = accepted.reader(io, &arbuf);
        var asw = accepted.writer(io, &awbuf);
        try ctHandshake(&asr.interface, &asw.interface);

        const s = try client.openStream(.{ .path = "/stall-body" }, true);
        defer s.close();
        const resp = [_]u8{0x88};
        try ctWrite(&asw.interface, .headers, p2.flag_end_headers, 1, &resp);
        // Announce a 10-byte DATA frame, send only 2 bytes of payload, then stall.
        var hdr: [11]u8 = undefined;
        p2.putHeader(hdr[0..9], 10, .data, p2.flag_end_stream, 1);
        hdr[9] = 'a';
        hdr[10] = 'b';
        try asw.interface.writeAll(&hdr);
        try asw.interface.flush();

        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        _ = try s.readEvent(arena_state.allocator()); // .headers
        const start = Io.Timestamp.now(io, .awake).nanoseconds;
        try testing.expectError(error.ConnectionClosed, s.readEvent(arena_state.allocator()));
        const elapsed_ms = @divFloor(Io.Timestamp.now(io, .awake).nanoseconds - start, std.time.ns_per_ms);
        try testing.expect(elapsed_ms < 2_000);
    }
    {
        // Part B: deinit wakes within reader_wake_ms (~50ms) even when keepalive_time_ms is 60s
        // and the socket was NOT closed beforehand.
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
        client.setKeepalive(60_000, 60_000);

        var arbuf: [4096]u8 = undefined;
        var awbuf: [4096]u8 = undefined;
        var asr = accepted.reader(io, &arbuf);
        var asw = accepted.writer(io, &awbuf);
        try ctHandshake(&asr.interface, &asw.interface);
        Io.sleep(io, .{ .nanoseconds = 30 * std.time.ns_per_ms }, .awake) catch {};

        const start = Io.Timestamp.now(io, .awake).nanoseconds;
        client.deinit();
        const elapsed_ms = @divFloor(Io.Timestamp.now(io, .awake).nanoseconds - start, std.time.ns_per_ms);
        try testing.expect(elapsed_ms < 1_000);
    }
}

test "Client.writeFrame poisons subsequent writes after a partial write failure" {
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
    var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };
    var client: Client = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .r = &dummy_r,
        .w = &sink.writer,
        .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
    };
    defer client.dec.deinit();

    const zero_ping: [8]u8 = @splat(0);
    try testing.expectError(error.WriteFailed, client.writeFrame(.ping, 0, 0, &zero_ping));
    try testing.expect(client.write_broken);
    try testing.expectError(error.WriteFailed, client.writeFrame(.settings, p2.flag_ack, 0, ""));
}

test "client rejects te in response headers/trailers and non-tchar header names (#37)" {
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

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Stream 1: response headers containing `te: trailers` -> RST(PROTOCOL_ERROR).
    {
        const s = try client.openStream(.{ .path = "/te-resp" }, true);
        defer s.close();
        var blk: std.ArrayList(u8) = .empty;
        try blk.append(arena, 0x88); // :status 200
        try hpack.Encoder.encodeTrailers(arena, &blk, &.{.{ .name = "te", .value = "trailers" }});
        try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, s.id, blk.items);
        const ev = try s.readEvent(arena);
        try testing.expect(ev == .rst);
        try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), ev.rst.code);
    }

    // Stream 3: response trailers containing `te: trailers` -> RST(PROTOCOL_ERROR).
    {
        const s = try client.openStream(.{ .path = "/te-trailer" }, true);
        defer s.close();
        const ok200 = [_]u8{0x88};
        try ctWrite(&asw.interface, .headers, p2.flag_end_headers, s.id, &ok200);
        const ev1 = try s.readEvent(arena);
        try testing.expect(ev1 == .headers);

        var tblk: std.ArrayList(u8) = .empty;
        try hpack.Encoder.encodeTrailers(arena, &tblk, &.{.{ .name = "te", .value = "trailers" }});
        try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, s.id, tblk.items);
        const ev2 = try s.readEvent(arena);
        try testing.expect(ev2 == .rst);
        try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), ev2.rst.code);
    }

    // Stream 5: response header name containing delimiter `;` -> RST(PROTOCOL_ERROR).
    {
        const s = try client.openStream(.{ .path = "/bad-tchar" }, true);
        defer s.close();
        var blk: std.ArrayList(u8) = .empty;
        try blk.append(arena, 0x88); // :status 200
        try hpack.Encoder.encodeTrailers(arena, &blk, &.{.{ .name = "bad;hdr", .value = "x" }});
        try ctWrite(&asw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, s.id, blk.items);
        const ev = try s.readEvent(arena);
        try testing.expect(ev == .rst);
        try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.protocol_error)), ev.rst.code);
    }
}

test "client catches intermediate SETTINGS_INITIAL_WINDOW_SIZE overflow in one frame (#38)" {
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

    const s = try client.openStream(.{ .path = "/order" }, false);
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, 0x7fff_ffff - 65535, .big);
    try ctWrite(&asw.interface, .window_update, 0, 1, &wu);

    // One SETTINGS frame: raise to 65536 (overflows stream 1 past 2^31-1!), then
    // immediately lower back to 65535. RFC 9113 §6.5 requires in-order application.
    var st: [12]u8 = undefined;
    p2.putSetting(st[0..6], p2.set_initial_window_size, 65536);
    p2.putSetting(st[6..12], p2.set_initial_window_size, 65535);
    try ctWrite(&asw.interface, .settings, 0, 0, &st);

    try waitDead(io, &client, 3000);
    const code = try ctReadGoawayCode(testing.allocator, &asr.interface);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.flow_control_error)), code);
    s.close();
    client.deinit();
}

test "client initWithConfig advertises receive windows, accepts >64KiB in flight, and batches/coalesces WINDOW_UPDATE (#39)" {
    const io = testing.io;
    // Part A: handshake advertises INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE, and stream-0 WINDOW_UPDATE.
    {
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
        defer srv.deinit(io);
        const port = srv.socket.address.ip4.port;
        const caddr = try net.IpAddress.parse("127.0.0.1", port);
        const cstream = try caddr.connect(io, .{ .mode = .stream });
        defer cstream.close(io);
        var accepted = try srv.accept(io);
        defer accepted.close(io);

        var crbuf: [8192]u8 = undefined;
        var cwbuf: [8192]u8 = undefined;
        var csr = cstream.reader(io, &crbuf);
        var csw = cstream.writer(io, &cwbuf);
        var client: Client = undefined;
        try client.initWithConfig(io, testing.allocator, &csr.interface, &csw.interface, .{
            .connection_window_size = 1 << 20,
            .initial_window_size = 512 * 1024,
        });
        defer client.deinit();

        var arbuf: [8192]u8 = undefined;
        var awbuf: [65536]u8 = undefined;
        var asr = accepted.reader(io, &arbuf);
        var asw = accepted.writer(io, &awbuf);
        var pf: [p2.preface.len]u8 = undefined;
        try asr.interface.readSliceAll(&pf);

        var settings = try ctRead(testing.allocator, &asr.interface);
        defer settings.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.settings, settings.hdr.ftype);
        var adv_iw: ?u32 = null;
        var adv_mhls: ?u32 = null;
        var i: usize = 0;
        while (i + 6 <= settings.payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, settings.payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, settings.payload[i + 2 ..][0..4], .big);
            if (id == p2.set_initial_window_size) adv_iw = val;
            if (id == p2.set_max_header_list_size) adv_mhls = val;
        }
        try testing.expectEqual(@as(?u32, 512 * 1024), adv_iw);
        try testing.expectEqual(@as(?u32, @intCast(hpack.default_max_header_list_size)), adv_mhls);

        try ctWrite(&asw.interface, .settings, 0, 0, "");
        var conn_incr: ?u32 = null;
        while (true) {
            var f = try ctRead(testing.allocator, &asr.interface);
            defer f.deinit(testing.allocator);
            if (f.hdr.ftype == .window_update and f.hdr.sid == 0) {
                conn_incr = std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
            }
            if (f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0)) break;
        }
        try testing.expectEqual(@as(?u32, (1 << 20) - 65535), conn_incr);

        // Push 6 × 16 KiB = 96 KiB BEFORE the caller consumes anything: must succeed.
        const s = try client.openStream(.{ .path = "/big" }, true);
        defer s.close();
        var hf = try ctRead(testing.allocator, &asr.interface);
        defer hf.deinit(testing.allocator);
        const resp = [_]u8{0x88};
        try ctWrite(&asw.interface, .headers, p2.flag_end_headers, hf.hdr.sid, &resp);
        var chunk: [16384]u8 = @splat('z');
        for (0..6) |_| try ctWrite(&asw.interface, .data, 0, hf.hdr.sid, &chunk);
        try ctWrite(&asw.interface, .data, p2.flag_end_stream, hf.hdr.sid, "");
        Io.sleep(io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};

        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        var got: usize = 0;
        while (true) {
            switch (try s.readEvent(arena_state.allocator())) {
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

    // Part B: writeWindowUpdates coalesces conn + stream WINDOW_UPDATE into 1 flush.
    {
        const FlushCounter = struct {
            flushes: usize = 0,
            bytes: std.ArrayList(u8) = .empty,
            writer: Io.Writer,

            fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
                const self: *@This() = @fieldParentPtr("writer", w);
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
        var buf: [256]u8 = undefined;
        var fc: FlushCounter = .{
            .writer = .{ .buffer = &buf, .vtable = &.{ .drain = FlushCounter.drain } },
        };
        defer fc.bytes.deinit(testing.allocator);
        var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };
        var client: Client = .{
            .io = io,
            .gpa = testing.allocator,
            .r = &dummy_r,
            .w = &fc.writer,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
            .cfg = .{ .connection_window_size = 65535, .initial_window_size = 65535 },
            .conn_recv_window = 65535,
        };
        defer client.dec.deinit();
        defer client.streams.deinit(testing.allocator);

        const st = try testing.allocator.create(Stream);
        defer testing.allocator.destroy(st);
        st.* = .{ .client = &client, .id = 1, .send_window = 65535, .recv_window = 65535 };
        try client.streams.put(testing.allocator, 1, st);
        defer _ = client.streams.remove(1);

        // Consuming 10000 B (< 32767 half-window) emits 0 flushes / 0 WINDOW_UPDATEs.
        client.conn_recv_window -= 40000;
        st.recv_window -= 40000;
        client.replenish(1, 10000);
        try testing.expectEqual(@as(usize, 0), fc.flushes);
        client.replenish(1, 10000);
        try testing.expectEqual(@as(usize, 0), fc.flushes);

        // Consuming another 20000 B (total 40000 B >= 32767) emits BOTH conn + stream
        // WINDOW_UPDATE frames (2 × 13 = 26 bytes) in ONE single flush!
        client.replenish(1, 20000);
        try testing.expectEqual(@as(usize, 1), fc.flushes);
        try testing.expectEqual(@as(usize, 26), fc.bytes.items.len);
        const f1 = p2.parseHeader(fc.bytes.items[0..9]);
        const f2 = p2.parseHeader(fc.bytes.items[13..22]);
        try testing.expectEqual(p2.FrameType.window_update, f1.ftype);
        try testing.expectEqual(@as(u31, 0), f1.sid);
        try testing.expectEqual(@as(u32, 40000), std.mem.readInt(u32, fc.bytes.items[9..13], .big));
        try testing.expectEqual(p2.FrameType.window_update, f2.ftype);
        try testing.expectEqual(@as(u31, 1), f2.sid);
        try testing.expectEqual(@as(u32, 40000), std.mem.readInt(u32, fc.bytes.items[22..26], .big));
    }
}

test "idle client without keepalive does not poll every 50ms and wakes promptly on deinit (#40)" {
    const CountingReader = struct {
        inner: *Io.Reader,
        calls: std.atomic.Value(usize) = .init(0),
        reader: Io.Reader,

        fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const self: *@This() = @fieldParentPtr("reader", r);
            _ = self.calls.fetchAdd(1, .monotonic);
            return self.inner.stream(w, limit);
        }

        fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
            const self: *@This() = @fieldParentPtr("reader", r);
            _ = self.calls.fetchAdd(1, .monotonic);
            return self.inner.readVec(data);
        }
    };

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
    var counting: CountingReader = .{
        .inner = &csr.interface,
        .reader = .{
            .buffer = &.{},
            .seek = 0,
            .end = 0,
            .vtable = &.{ .stream = CountingReader.stream, .readVec = CountingReader.readVec },
        },
    };
    var client: Client = undefined;
    try client.init(io, testing.allocator, &counting.reader, &csw.interface);

    var arbuf: [4096]u8 = undefined;
    var awbuf: [4096]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);
    // Wait until handshake ack is sent and reader settles into idle wait.
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }
    Io.sleep(io, .{ .nanoseconds = 30 * std.time.ns_per_ms }, .awake) catch {};
    const calls_before = counting.calls.load(.acquire);

    // Remain idle for 250 ms: old 50 ms polling loop caused ~5 extra readVec calls;
    // event-driven wakeup must cause 0 additional calls!
    Io.sleep(io, .{ .nanoseconds = 250 * std.time.ns_per_ms }, .awake) catch {};
    const calls_after_idle = counting.calls.load(.acquire);
    try testing.expectEqual(calls_before, calls_after_idle);

    // Enabling/reconfiguring keepalive and sending a keepalive PING must ALSO
    // never cancel or re-invoke the live `readVec` (PR #43 review #2).
    client.setKeepalive(60, 500);
    Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};
    client.setKeepalive(50, 500);
    var ping_frame = try ctRead(testing.allocator, &asr.interface);
    defer ping_frame.deinit(testing.allocator);
    try testing.expectEqual(p2.FrameType.ping, ping_frame.hdr.ftype);
    try testing.expectEqual(@as(u8, 0), ping_frame.hdr.flags & p2.flag_ack);
    try testing.expectEqual(calls_before, counting.calls.load(.acquire));

    // Reply with PING(ACK); the uninterrupted readVec receives it cleanly.
    try ctWrite(&asw.interface, .ping, p2.flag_ack, 0, ping_frame.payload);
    Io.sleep(io, .{ .nanoseconds = 30 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(!client.dead.load(.acquire));

    // deinit must still wake and join promptly without closing the socket beforehand.
    const start = Io.Timestamp.now(io, .awake).nanoseconds;
    client.deinit();
    const elapsed_ms = @divFloor(Io.Timestamp.now(io, .awake).nanoseconds - start, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 500);
}

test "client flushes sub-threshold connection credit on stream end and removeStream" {
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

    var crbuf: [8192]u8 = undefined;
    var cwbuf: [8192]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    // Default 1 MiB connection window -> half-window threshold is 512 KiB.
    try client.init(io, testing.allocator, &csr.interface, &csw.interface);
    defer client.deinit();

    var arbuf: [8192]u8 = undefined;
    var awbuf: [65536]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshake(&asr.interface, &asw.interface);
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Stream 1: receive 24 KiB (< 512 KiB threshold) with END_STREAM on the 2nd frame.
    const s1 = try client.openStream(.{ .path = "/sub-threshold" }, true);
    var req1 = try ctRead(testing.allocator, &asr.interface);
    req1.deinit(testing.allocator);
    const ok200 = [_]u8{0x88};
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, s1.id, &ok200);
    var chunk: [12000]u8 = @splat('c');
    try ctWrite(&asw.interface, .data, 0, s1.id, &chunk);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, s1.id, &chunk);

    _ = try s1.readEvent(arena); // headers
    _ = try s1.readEvent(arena); // chunk 1 (stream still open -> batched)
    _ = try s1.readEvent(arena); // chunk 2 (remote_closed -> flushes all 24000 B conn credit!)
    s1.close();

    const ping: [8]u8 = @splat(0x55);
    try ctWrite(&asw.interface, .ping, 0, 0, &ping);
    var conn_wu: u32 = 0;
    var stream_wu: u32 = 0;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update) {
            const incr = std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
            if (f.hdr.sid == 0) conn_wu += incr else stream_wu += incr;
        }
        if (f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack != 0)) break;
    }
    try testing.expectEqual(@as(u32, 24000), conn_wu);
    try testing.expectEqual(@as(u32, 0), stream_wu);

    // Stream 3: peer sends 12000 B (not END_STREAM), caller consumes nothing and closes.
    // `removeStream` must flush the 12000 B immediately instead of stranding it.
    const s3 = try client.openStream(.{ .path = "/unconsumed" }, true);
    var req3 = try ctRead(testing.allocator, &asr.interface);
    req3.deinit(testing.allocator);
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, s3.id, &ok200);
    try ctWrite(&asw.interface, .data, 0, s3.id, &chunk);
    // Fence via PING so readerLoop definitely queued the 12000 B before s3.close().
    try ctWrite(&asw.interface, .ping, 0, 0, &ping);
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        const is_pong = f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_pong) break;
    }
    s3.close();

    try ctWrite(&asw.interface, .ping, 0, 0, &ping);
    var conn_wu2: u32 = 0;
    while (true) {
        var f = try ctRead(testing.allocator, &asr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update and f.hdr.sid == 0) {
            conn_wu2 += std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
        }
        if (f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack != 0)) break;
    }
    try testing.expectEqual(@as(u32, 12000), conn_wu2);
}

test "waitReadChunk prioritizes real transport read errors over concurrent dead wakeup" {
    const ErrReader = struct {
        err: Io.Reader.Error,
        reader: Io.Reader,
        fn stream(r: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
            const self: *@This() = @fieldParentPtr("reader", r);
            return self.err;
        }
        fn readVec(r: *Io.Reader, _: [][]u8) Io.Reader.Error!usize {
            const self: *@This() = @fieldParentPtr("reader", r);
            return self.err;
        }
    };
    var dummy_w: Io.Writer = .{ .buffer = &.{}, .vtable = undefined };
    var dst: [9]u8 = undefined;
    const now = Io.Timestamp.now(testing.io, .awake).nanoseconds;

    // Case 1: `.work` fails with ReadFailed while connection is live -> ReadFailed.
    {
        var fr: ErrReader = .{
            .err = error.ReadFailed,
            .reader = .{
                .buffer = &.{},
                .seek = 0,
                .end = 0,
                .vtable = &.{ .stream = ErrReader.stream, .readVec = ErrReader.readVec },
            },
        };
        var client: Client = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .r = &fr.reader,
            .w = &dummy_w,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        };
        defer client.dec.deinit();
        try testing.expectError(error.ReadFailed, client.waitReadChunk(&dst, false, now));
    }

    // Case 2: `.work` returns EndOfStream even while `dead == true` -> EndOfStream wins.
    {
        var fr: ErrReader = .{
            .err = error.EndOfStream,
            .reader = .{
                .buffer = &.{},
                .seek = 0,
                .end = 0,
                .vtable = &.{ .stream = ErrReader.stream, .readVec = ErrReader.readVec },
            },
        };
        var client: Client = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .r = &fr.reader,
            .w = &dummy_w,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
            .dead = .init(true),
        };
        defer client.dec.deinit();
        try testing.expectError(error.EndOfStream, client.waitReadChunk(&dst, false, now));
    }
}

test "setKeepalive(0, 0) clears stale ping_outstanding before later re-enable" {
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const c_stream: net.Stream = .{ .socket = .{
        .handle = fds[0],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    const s_stream: net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var crbuf: [4096]u8 = undefined;
    var cwbuf: [4096]u8 = undefined;
    var srbuf: [4096]u8 = undefined;
    var swbuf: [4096]u8 = undefined;
    var cr = c_stream.reader(testing.io, &crbuf);
    var cw = c_stream.writer(testing.io, &cwbuf);
    var sr = s_stream.reader(testing.io, &srbuf);
    var sw = s_stream.writer(testing.io, &swbuf);

    var client: Client = undefined;
    try client.initWithConfig(testing.io, testing.allocator, &cr.interface, &cw.interface, .{
        .keepalive_time_ms = 40,
        .keepalive_timeout_ms = 2_000,
    });
    defer client.deinit();

    // Complete server handshake (preface + SETTINGS) and wait for keepalive PING
    // without replying, so `ping_outstanding` becomes true.
    try ctHandshake(&sr.interface, &sw.interface);
    while (true) {
        var f = try ctRead(testing.allocator, &sr.interface);
        const is_ping = f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack == 0);
        f.deinit(testing.allocator);
        if (is_ping) break;
    }
    try testing.expect(client.ping_outstanding.load(.acquire));

    // Disable keepalive; watcher must clear ping_outstanding.
    client.setKeepalive(0, 0);
    var waited: usize = 0;
    while (client.ping_outstanding.load(.acquire) and waited < 200) : (waited += 1) {
        Io.sleep(testing.io, .{ .nanoseconds = 2 * std.time.ns_per_ms }, .awake) catch {};
    }
    try testing.expect(!client.ping_outstanding.load(.acquire));

    // Re-enable with a long idle cadence (5s) and tiny timeout (20ms): if
    // ping_outstanding had stayed true, the connection would die in ~20ms.
    client.setKeepalive(5_000, 20);
    Io.sleep(testing.io, .{ .nanoseconds = 80 * std.time.ns_per_ms }, .awake) catch {};
    try testing.expect(!client.dead.load(.acquire));
}

test "openStreamWithBody coalesces HEADERS + DATA (+ END_STREAM) into a single flush (#44)" {
    const CountingWriter = struct {
        flushes: usize = 0,
        bytes: std.ArrayList(u8) = .empty,
        writer: Io.Writer,

        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", w);
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

    const parseWireFrames = struct {
        fn check(
            wire: []const u8,
            expect_sid: u31,
            expect_hdr_es: bool,
            expect_body: []const u8,
            expect_data_es: bool,
            expect_data_frames: usize,
        ) !void {
            var pos: usize = 0;
            var hdr_seen = false;
            var data_frames: usize = 0;
            var reassembled: std.ArrayList(u8) = .empty;
            defer reassembled.deinit(testing.allocator);

            while (pos < wire.len) {
                try testing.expect(pos + 9 <= wire.len);
                const fh = p2.parseHeader(wire[pos..][0..9]);
                pos += 9;
                try testing.expect(pos + fh.length <= wire.len);
                const payload = wire[pos .. pos + fh.length];
                pos += fh.length;
                try testing.expectEqual(expect_sid, fh.sid);
                if (!hdr_seen) {
                    try testing.expectEqual(p2.FrameType.headers, fh.ftype);
                    try testing.expect((fh.flags & p2.flag_end_headers) != 0);
                    try testing.expectEqual(expect_hdr_es, (fh.flags & p2.flag_end_stream) != 0);
                    hdr_seen = true;
                } else {
                    try testing.expectEqual(p2.FrameType.data, fh.ftype);
                    try testing.expect(payload.len <= 16384);
                    data_frames += 1;
                    const is_last = pos == wire.len;
                    const has_es = (fh.flags & p2.flag_end_stream) != 0;
                    if (is_last) {
                        try testing.expectEqual(expect_data_es, has_es);
                    } else {
                        try testing.expect(!has_es);
                    }
                    try reassembled.appendSlice(testing.allocator, payload);
                }
            }
            try testing.expect(hdr_seen);
            try testing.expectEqual(expect_data_frames, data_frames);
            try testing.expectEqualSlices(u8, expect_body, reassembled.items);
        }
    }.check;

    const wbuf = try testing.allocator.alloc(u8, 128 * 1024);
    defer testing.allocator.free(wbuf);
    var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };

    // Case 1: empty body + end_stream -> 1 flush, HEADERS(END_STREAM) only.
    {
        var cw: CountingWriter = .{ .writer = .{ .buffer = wbuf, .vtable = &.{ .drain = CountingWriter.drain } } };
        defer cw.bytes.deinit(testing.allocator);
        var client: Client = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .r = &dummy_r,
            .w = &cw.writer,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        };
        defer client.deinit();

        const st = try client.openStreamWithBody(.{ .method = "GET", .path = "/empty" }, "", true);
        try testing.expectEqual(@as(usize, 1), cw.flushes);
        try testing.expect(st.local_closed.load(.acquire));
        try parseWireFrames(cw.bytes.items, 1, true, "", false, 0);
    }

    // Case 2: small unary body + end_stream -> 1 flush, HEADERS + DATA(END_STREAM).
    {
        var cw: CountingWriter = .{ .writer = .{ .buffer = wbuf, .vtable = &.{ .drain = CountingWriter.drain } } };
        defer cw.bytes.deinit(testing.allocator);
        var client: Client = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .r = &dummy_r,
            .w = &cw.writer,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        };
        defer client.deinit();

        const payload = "hello grpc";
        const st = try client.openStreamWithBody(.{ .method = "POST", .path = "/svc/Echo" }, payload, true);
        try testing.expectEqual(@as(usize, 1), cw.flushes);
        try testing.expect(st.local_closed.load(.acquire));
        try testing.expectEqual(p2.default_window - @as(i64, payload.len), st.send_window);
        try testing.expectEqual(p2.default_window - @as(i64, payload.len), client.conn_send_window);
        try parseWireFrames(cw.bytes.items, 1, false, payload, true, 1);
    }

    // Case 3: multi-frame body (36000 B <= 64 KiB batch cap & 65535 window) -> 1 flush, 1 HEADERS + 3 DATA.
    {
        var cw: CountingWriter = .{ .writer = .{ .buffer = wbuf, .vtable = &.{ .drain = CountingWriter.drain } } };
        defer cw.bytes.deinit(testing.allocator);
        var client: Client = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .r = &dummy_r,
            .w = &cw.writer,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        };
        defer client.deinit();

        const body = try testing.allocator.alloc(u8, 36_000);
        defer testing.allocator.free(body);
        for (body, 0..) |*b, idx| b.* = @truncate(idx);

        const st = try client.openStreamWithBody(.{ .method = "POST", .path = "/multi" }, body, true);
        try testing.expectEqual(@as(usize, 1), cw.flushes);
        try testing.expect(st.local_closed.load(.acquire));
        try testing.expectEqual(p2.default_window - @as(i64, @intCast(body.len)), st.send_window);
        try parseWireFrames(cw.bytes.items, 1, false, body, true, 3);
    }

    // Case 4: initial payload with end_stream=false -> 1 flush, stream stays open for later send().
    {
        var cw: CountingWriter = .{ .writer = .{ .buffer = wbuf, .vtable = &.{ .drain = CountingWriter.drain } } };
        defer cw.bytes.deinit(testing.allocator);
        var client: Client = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .r = &dummy_r,
            .w = &cw.writer,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        };
        defer client.deinit();

        const st = try client.openStreamWithBody(.{ .method = "POST", .path = "/bidi" }, "head", false);
        try testing.expectEqual(@as(usize, 1), cw.flushes);
        try testing.expect(!st.local_closed.load(.acquire));
        try parseWireFrames(cw.bytes.items, 1, false, "head", false, 1);

        try st.send("-tail", true);
        try testing.expectEqual(@as(usize, 2), cw.flushes);
        try testing.expect(st.local_closed.load(.acquire));
        try parseWireFrames(cw.bytes.items, 1, false, "head-tail", true, 2);
    }
}

test "Stream.send batches multi-frame DATA into bounded single-flush writes (#44)" {
    const CountingWriter = struct {
        flushes: usize = 0,
        bytes: std.ArrayList(u8) = .empty,
        writer: Io.Writer,

        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", w);
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

    const wbuf = try testing.allocator.alloc(u8, 128 * 1024);
    defer testing.allocator.free(wbuf);
    var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };
    var cw: CountingWriter = .{ .writer = .{ .buffer = wbuf, .vtable = &.{ .drain = CountingWriter.drain } } };
    defer cw.bytes.deinit(testing.allocator);

    var client: Client = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .r = &dummy_r,
        .w = &cw.writer,
        .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        .conn_send_window = 256 * 1024,
        .peer_initial_window = .init(256 * 1024),
    };
    defer client.deinit();

    const st = try client.openStream(.{ .method = "POST", .path = "/upload" }, false);
    cw.flushes = 0;
    cw.bytes.clearRetainingCapacity();

    // 40000 B fits inside one 64 KiB batch -> 1 flush, 3 DATA frames (16384 + 16384 + 7232).
    const chunk1 = try testing.allocator.alloc(u8, 40_000);
    defer testing.allocator.free(chunk1);
    for (chunk1, 0..) |*b, idx| b.* = @truncate(idx);
    try st.send(chunk1, false);
    try testing.expectEqual(@as(usize, 1), cw.flushes);

    var pos: usize = 0;
    var frames: usize = 0;
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    while (pos < cw.bytes.items.len) {
        const fh = p2.parseHeader(cw.bytes.items[pos..][0..9]);
        pos += 9;
        try testing.expectEqual(p2.FrameType.data, fh.ftype);
        try testing.expect(fh.length <= 16384);
        try testing.expect((fh.flags & p2.flag_end_stream) == 0);
        try got.appendSlice(testing.allocator, cw.bytes.items[pos .. pos + fh.length]);
        pos += fh.length;
        frames += 1;
    }
    try testing.expectEqual(@as(usize, 3), frames);
    try testing.expectEqualSlices(u8, chunk1, got.items);

    // 140000 B splits across 3 bounded 64 KiB batches (65536 + 65536 + 8928) -> 3 flushes, 9 frames.
    cw.flushes = 0;
    cw.bytes.clearRetainingCapacity();
    got.clearRetainingCapacity();
    const chunk2 = try testing.allocator.alloc(u8, 140_000);
    defer testing.allocator.free(chunk2);
    for (chunk2, 0..) |*b, idx| b.* = @truncate(idx *% 3);
    try st.send(chunk2, true);
    try testing.expectEqual(@as(usize, 3), cw.flushes);
    try testing.expect(st.local_closed.load(.acquire));

    pos = 0;
    frames = 0;
    while (pos < cw.bytes.items.len) {
        const fh = p2.parseHeader(cw.bytes.items[pos..][0..9]);
        pos += 9;
        try testing.expectEqual(p2.FrameType.data, fh.ftype);
        try testing.expect(fh.length <= 16384);
        const is_last = pos + fh.length == cw.bytes.items.len;
        try testing.expectEqual(is_last, (fh.flags & p2.flag_end_stream) != 0);
        try got.appendSlice(testing.allocator, cw.bytes.items[pos .. pos + fh.length]);
        pos += fh.length;
        frames += 1;
    }
    try testing.expectEqual(@as(usize, 9), frames);
    try testing.expectEqualSlices(u8, chunk2, got.items);
}

test "openStreamWithBody handles zero/partial initial window and cleans up on remainder reset (#44)" {
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const c_stream: net.Stream = .{ .socket = .{
        .handle = fds[0],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    const s_stream: net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var crbuf: [8192]u8 = undefined;
    var cwbuf: [8192]u8 = undefined;
    var srbuf: [8192]u8 = undefined;
    var swbuf: [8192]u8 = undefined;
    var cr = c_stream.reader(testing.io, &crbuf);
    var cw = c_stream.writer(testing.io, &cwbuf);
    var sr = s_stream.reader(testing.io, &srbuf);
    var sw = s_stream.writer(testing.io, &swbuf);

    var client: Client = undefined;
    try client.init(testing.io, testing.allocator, &cr.interface, &cw.interface);
    defer client.deinit();

    try ctHandshake(&sr.interface, &sw.interface);
    while (true) {
        var f = try ctRead(testing.allocator, &sr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    const setPeerInitWin = struct {
        fn send(r: *Io.Reader, w: *Io.Writer, iw: u32) !void {
            var sp: [6]u8 = undefined;
            p2.putSetting(&sp, p2.set_initial_window_size, iw);
            try ctWrite(w, .settings, 0, 0, &sp);
            while (true) {
                var f = try ctRead(testing.allocator, r);
                const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
                f.deinit(testing.allocator);
                if (is_ack) break;
            }
        }
    }.send;

    const Opener = struct {
        client: *Client,
        path: []const u8,
        body: []const u8,
        stream: ?*Stream = null,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            if (self.client.openStreamWithBody(.{ .method = "POST", .path = self.path }, self.body, true)) |s| {
                self.stream = s;
            } else |e| {
                self.err = e;
            }
        }
    };

    // Part A: initial window == 0 -> HEADERS flushes, DATA waits for WINDOW_UPDATE.
    try setPeerInitWin(&sr.interface, &sw.interface, 0);
    {
        var op: Opener = .{ .client = &client, .path = "/zero-win", .body = "deferred-payload" };
        const th = try std.Thread.spawn(.{}, Opener.run, .{&op});

        var h = try ctRead(testing.allocator, &sr.interface);
        defer h.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.headers, h.hdr.ftype);
        try testing.expect((h.hdr.flags & p2.flag_end_stream) == 0);
        const sid = h.hdr.sid;

        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, 1024, .big);
        try ctWrite(&sw.interface, .window_update, 0, sid, &wu);

        var d = try ctRead(testing.allocator, &sr.interface);
        defer d.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.data, d.hdr.ftype);
        try testing.expectEqual(sid, d.hdr.sid);
        try testing.expect((d.hdr.flags & p2.flag_end_stream) != 0);
        try testing.expectEqualStrings("deferred-payload", d.payload);

        th.join();
        try testing.expect(op.err == null);
        const s = op.stream.?;
        try testing.expect(s.local_closed.load(.acquire));
        const ok200 = [_]u8{0x88};
        try ctWrite(&sw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, sid, &ok200);
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        _ = try s.readEvent(arena.allocator());
        s.close();
    }

    // Part B: partial initial window (8 B) -> HEADERS + 8 B coalesced, tail sent after WINDOW_UPDATE.
    try setPeerInitWin(&sr.interface, &sw.interface, 8);
    {
        var op: Opener = .{ .client = &client, .path = "/partial-win", .body = "01234567abcdefgh" };
        const th = try std.Thread.spawn(.{}, Opener.run, .{&op});

        var h = try ctRead(testing.allocator, &sr.interface);
        defer h.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.headers, h.hdr.ftype);
        try testing.expect((h.hdr.flags & p2.flag_end_stream) == 0);
        const sid = h.hdr.sid;

        var d1 = try ctRead(testing.allocator, &sr.interface);
        defer d1.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.data, d1.hdr.ftype);
        try testing.expect((d1.hdr.flags & p2.flag_end_stream) == 0);
        try testing.expectEqualStrings("01234567", d1.payload);

        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, 1024, .big);
        try ctWrite(&sw.interface, .window_update, 0, sid, &wu);

        var d2 = try ctRead(testing.allocator, &sr.interface);
        defer d2.deinit(testing.allocator);
        try testing.expectEqual(p2.FrameType.data, d2.hdr.ftype);
        try testing.expect((d2.hdr.flags & p2.flag_end_stream) != 0);
        try testing.expectEqualStrings("abcdefgh", d2.payload);

        th.join();
        try testing.expect(op.err == null);
        const s = op.stream.?;
        const ok200 = [_]u8{0x88};
        try ctWrite(&sw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, sid, &ok200);
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        _ = try s.readEvent(arena.allocator());
        s.close();
    }

    // Part C: remainder send interrupted by RST_STREAM -> returns StreamReset & reclaims stream + slot.
    try setPeerInitWin(&sr.interface, &sw.interface, 4);
    {
        var op: Opener = .{ .client = &client, .path = "/rst-tail", .body = "0123blocked-tail" };
        const th = try std.Thread.spawn(.{}, Opener.run, .{&op});

        var h = try ctRead(testing.allocator, &sr.interface);
        defer h.deinit(testing.allocator);
        const sid = h.hdr.sid;
        var d1 = try ctRead(testing.allocator, &sr.interface);
        defer d1.deinit(testing.allocator);
        try testing.expectEqualStrings("0123", d1.payload);

        var rst: [4]u8 = undefined;
        std.mem.writeInt(u32, &rst, @backingInt(p2.ErrorCode.cancel), .big);
        try ctWrite(&sw.interface, .rst_stream, 0, sid, &rst);

        th.join();
        try testing.expectEqual(@as(?anyerror, error.StreamReset), op.err);
        try testing.expect(op.stream == null);

        client.streams_mu.lockUncancelable(testing.io);
        const remaining_streams = client.streams.count();
        client.streams_mu.unlock(testing.io);
        try testing.expectEqual(@as(usize, 0), remaining_streams);

        client.admit_mu.lockUncancelable(testing.io);
        const active = client.active_streams;
        client.admit_mu.unlock(testing.io);
        try testing.expectEqual(@as(u32, 0), active);
    }
}

const GateAlloc = struct {
    child: std.mem.Allocator,
    io: Io,
    armed: std.atomic.Value(bool) = .init(false),
    gate_open: std.atomic.Value(bool) = .init(false),
    closed_count: std.atomic.Value(u32) = .init(0),
    expect_closed: u32 = 0,
    deinit_tid: std.Thread.Id = undefined,
    mu: Io.Mutex = .init,
    freed: std.AutoHashMapUnmanaged(usize, void) = .empty,
    gate_hits: std.atomic.Value(u32) = .init(0),

    fn allocator(self: *GateAlloc) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *GateAlloc = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(len, alignment, ret_addr);
        if (p) |ptr| {
            if (len == @sizeOf(Stream)) {
                self.mu.lockUncancelable(self.io);
                defer self.mu.unlock(self.io);
                _ = self.freed.remove(@intFromPtr(ptr));
            }
        }
        return p;
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *GateAlloc = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *GateAlloc = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *GateAlloc = @ptrCast(@alignCast(ctx));
        const is_stream = memory.len == @sizeOf(Stream);
        if (is_stream) {
            const addr = @intFromPtr(memory.ptr);
            {
                self.mu.lockUncancelable(self.io);
                defer self.mu.unlock(self.io);
                if (self.freed.contains(addr)) {
                    @panic("double free of *Stream (Client.deinit free loop raced Stream.close)");
                }
                self.freed.put(std.heap.page_allocator, addr, {}) catch @panic("oom");
            }
        }
        if (is_stream and self.armed.load(.acquire) and std.Thread.getCurrentId() == self.deinit_tid and self.gate_hits.load(.acquire) == 0) {
            self.gate_hits.store(1, .release);
            self.gate_open.store(true, .release);
            var spins: u32 = 0;
            while (self.closed_count.load(.acquire) < self.expect_closed and spins < 300) : (spins += 1) {
                Io.sleep(self.io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
            }
        }
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

const ReproCtx = struct { s: *Stream, g: *GateAlloc, err: ?anyerror = null };

fn reproCloser(ctx: *ReproCtx) void {
    const payload = @as([16]u8, @splat('x'));
    ctx.s.send(&payload, false) catch |e| {
        ctx.err = e;
    };
    while (!ctx.g.gate_open.load(.acquire)) std.atomic.spinLoopHint();
    ctx.s.close();
    _ = ctx.g.closed_count.fetchAdd(1, .release);
}

test "Client.deinit stream free loop does not double-free or race Stream.close (#46)" {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer srv.deinit(io);
    const port = srv.socket.address.ip4.port;
    const caddr = try net.IpAddress.parse("127.0.0.1", port);
    const cstream = try caddr.connect(io, .{ .mode = .stream });
    var accepted = try srv.accept(io);

    var gate = GateAlloc{ .child = testing.allocator, .io = io };
    var crbuf: [65536]u8 = undefined;
    var cwbuf: [65536]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.initWithConfig(io, gate.allocator(), &csr.interface, &csw.interface, .{ .connection_window_size = 65535 });

    var arbuf: [65536]u8 = undefined;
    var awbuf: [65536]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshakeFloor(&asr.interface, &asw.interface);
    var ack1 = try ctRead(testing.allocator, &asr.interface);
    ack1.deinit(testing.allocator);

    // Zero initial stream window so every send() parks in send_cond.
    var iw: [6]u8 = undefined;
    p2.putSetting(&iw, p2.set_initial_window_size, 0);
    try ctWrite(&asw.interface, .settings, 0, 0, &iw);
    var ack2 = try ctRead(testing.allocator, &asr.interface);
    ack2.deinit(testing.allocator);

    const m = 6;
    var ctxs: [m]ReproCtx = undefined;
    var ths: [m]std.Thread = undefined;
    for (0..m) |i| {
        const s = try client.openStream(.{ .path = "/x" }, false);
        ctxs[i] = .{ .s = s, .g = &gate };
    }
    for (0..m) |i| ths[i] = try std.Thread.spawn(.{}, reproCloser, .{&ctxs[i]});
    Io.sleep(io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};

    gate.armed.store(true, .release);
    gate.deinit_tid = std.Thread.getCurrentId();
    gate.expect_closed = m;
    client.deinit();
    for (0..m) |i| ths[i].join();
    for (0..m) |i| try testing.expectEqual(@as(?anyerror, error.ConnectionClosed), ctxs[i].err);

    cstream.close(io);
    accepted.close(io);
    gate.freed.deinit(std.heap.page_allocator);
}

test "Client.deinit waits for an already in-flight Stream.close before returning (#46)" {
    const PauseFreeAlloc = struct {
        child: std.mem.Allocator,
        io: Io,
        armed: std.atomic.Value(bool) = .init(false),
        in_free: std.atomic.Value(bool) = .init(false),

        fn allocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
        }
        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.child.rawAlloc(len, alignment, ret_addr);
        }
        fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.child.rawResize(memory, alignment, new_len, ret_addr);
        }
        fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.child.rawRemap(memory, alignment, new_len, ret_addr);
        }
        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (memory.len == @sizeOf(Stream) and self.armed.swap(false, .acq_rel)) {
                self.in_free.store(true, .release);
                Io.sleep(self.io, .{ .nanoseconds = 40 * std.time.ns_per_ms }, .awake) catch {};
            }
            self.child.rawFree(memory, alignment, ret_addr);
        }
    };

    const Closer = struct {
        s: *Stream,
        done: std.atomic.Value(bool) = .init(false),
        fn run(self: *@This()) void {
            self.s.close();
            self.done.store(true, .release);
        }
    };

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

    var palloc = PauseFreeAlloc{ .child = testing.allocator, .io = io };
    var crbuf: [16384]u8 = undefined;
    var cwbuf: [16384]u8 = undefined;
    var csr = cstream.reader(io, &crbuf);
    var csw = cstream.writer(io, &cwbuf);
    var client: Client = undefined;
    try client.initWithConfig(io, palloc.allocator(), &csr.interface, &csw.interface, .{ .connection_window_size = 65535 });

    var arbuf: [16384]u8 = undefined;
    var awbuf: [16384]u8 = undefined;
    var asr = accepted.reader(io, &arbuf);
    var asw = accepted.writer(io, &awbuf);
    try ctHandshakeFloor(&asr.interface, &asw.interface);
    var ack1 = try ctRead(testing.allocator, &asr.interface);
    ack1.deinit(testing.allocator);

    const s = try client.openStream(.{ .path = "/in-flight-close" }, true);
    var req_hdr = try ctRead(testing.allocator, &asr.interface);
    req_hdr.deinit(testing.allocator);

    // Queue an unconsumed response with DATA so `removeStream` has post-destroy
    // credit accounting work left after freeing `*Stream`.
    const ok200 = [_]u8{0x88};
    try ctWrite(&asw.interface, .headers, p2.flag_end_headers, s.id, &ok200);
    try ctWrite(&asw.interface, .data, p2.flag_end_stream, s.id, "unconsumed");
    Io.sleep(io, .{ .nanoseconds = 20 * std.time.ns_per_ms }, .awake) catch {};

    palloc.armed.store(true, .release);
    var closer = Closer{ .s = s };
    const th = try std.Thread.spawn(.{}, Closer.run, .{&closer});
    while (!palloc.in_free.load(.acquire)) std.atomic.spinLoopHint();

    // `s.close()` was started legally BEFORE `deinit()` began and is currently
    // mid-flight inside `removeStream`; `deinit()` must wait for it to finish.
    client.deinit();
    try testing.expect(closer.done.load(.acquire));
    th.join();
}

test "Client.Config.max_frame_size advertises larger inbound limit, accepts >16KiB DATA, and rejects oversize" {
    const io = testing.io;
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const c_stream: net.Stream = .{ .socket = .{
        .handle = fds[0],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    const s_stream: net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var crbuf: [65536]u8 = undefined;
    var cwbuf: [16384]u8 = undefined;
    var srbuf: [16384]u8 = undefined;
    var swbuf: [65536]u8 = undefined;
    var cr = c_stream.reader(io, &crbuf);
    var cw = c_stream.writer(io, &cwbuf);
    var sr = s_stream.reader(io, &srbuf);
    var sw = s_stream.writer(io, &swbuf);

    var client: Client = undefined;
    try client.initWithConfig(io, testing.allocator, &cr.interface, &cw.interface, .{
        .max_frame_size = 65536,
        .connection_window_size = 1 << 20,
        .initial_window_size = 1 << 20,
    });
    defer client.deinit();

    var pf: [p2.preface.len]u8 = undefined;
    try sr.interface.readSliceAll(&pf);
    var c_settings = try ctRead(testing.allocator, &sr.interface);
    defer c_settings.deinit(testing.allocator);
    var adv_mfs: ?u32 = null;
    var i: usize = 0;
    while (i + 6 <= c_settings.payload.len) : (i += 6) {
        const id = std.mem.readInt(u16, c_settings.payload[i..][0..2], .big);
        const val = std.mem.readInt(u32, c_settings.payload[i + 2 ..][0..4], .big);
        if (id == p2.set_max_frame_size) adv_mfs = val;
    }
    try testing.expectEqual(@as(?u32, 65536), adv_mfs);

    try ctWrite(&sw.interface, .settings, 0, 0, "");
    while (true) {
        var f = try ctRead(testing.allocator, &sr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    // Stream 1: single 40,000-byte DATA frame (> 16384 default) succeeds cleanly.
    const s1 = try client.openStream(.{ .path = "/large-frame" }, true);
    var req1 = try ctRead(testing.allocator, &sr.interface);
    req1.deinit(testing.allocator);

    const ok200 = [_]u8{0x88};
    try ctWrite(&sw.interface, .headers, p2.flag_end_headers, s1.id, &ok200);
    const big_frame = try testing.allocator.alloc(u8, 40_000);
    defer testing.allocator.free(big_frame);
    for (big_frame, 0..) |*b, idx| b.* = @truncate(idx *% 9);
    try ctWrite(&sw.interface, .data, p2.flag_end_stream, s1.id, big_frame);

    var hdr_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer hdr_arena.deinit();
    const ev = try s1.readEvent(hdr_arena.allocator());
    try testing.expect(ev == .headers);

    const got = try testing.allocator.alloc(u8, 40_000);
    defer testing.allocator.free(got);
    var off: usize = 0;
    while (true) {
        var tmp: [16384]u8 = undefined;
        const n = try s1.readBody(&tmp);
        if (n == 0) break;
        @memcpy(got[off .. off + n], tmp[0..n]);
        off += n;
    }
    try testing.expectEqual(@as(usize, 40_000), off);
    try testing.expectEqualSlices(u8, big_frame, got);
    s1.close();

    // Frame header > 65536 still triggers GOAWAY(FRAME_SIZE_ERROR).
    try ctWriteHeaderOnly(&sw.interface, .data, 1, 70_000);
    const code = try ctReadGoawayCode(testing.allocator, &sr.interface);
    try testing.expectEqual(@as(u32, @backingInt(p2.ErrorCode.frame_size_error)), code);
}

test "Stream.readBody and bodyReader stream multi-frame, padded, and trailer responses with zero arena growth" {
    const io = testing.io;
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const c_stream: net.Stream = .{ .socket = .{
        .handle = fds[0],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    const s_stream: net.Stream = .{ .socket = .{
        .handle = fds[1],
        .address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable,
    } };
    var crbuf: [8192]u8 = undefined;
    var cwbuf: [8192]u8 = undefined;
    var srbuf: [8192]u8 = undefined;
    var swbuf: [32768]u8 = undefined;
    var cr = c_stream.reader(io, &crbuf);
    var cw = c_stream.writer(io, &cwbuf);
    var sr = s_stream.reader(io, &srbuf);
    var sw = s_stream.writer(io, &swbuf);

    var client: Client = undefined;
    try client.initWithConfig(io, testing.allocator, &cr.interface, &cw.interface, .{
        .connection_window_size = 65535,
        .initial_window_size = 65535,
    });
    defer client.deinit();

    try ctHandshakeFloor(&sr.interface, &sw.interface);
    while (true) {
        var f = try ctRead(testing.allocator, &sr.interface);
        const is_ack = f.hdr.ftype == .settings and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_ack) break;
    }

    const s = try client.openStream(.{ .path = "/stream-body" }, true);
    defer s.close();
    var req = try ctRead(testing.allocator, &sr.interface);
    req.deinit(testing.allocator);

    // Calling readBody before consuming initial response headers returns HeadersPending.
    const ok200 = [_]u8{0x88};
    try ctWrite(&sw.interface, .headers, p2.flag_end_headers, s.id, &ok200);
    // Fence via PING so headers are queued.
    const ping: [8]u8 = @splat(0x33);
    try ctWrite(&sw.interface, .ping, 0, 0, &ping);
    while (true) {
        var f = try ctRead(testing.allocator, &sr.interface);
        const is_pong = f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack != 0);
        f.deinit(testing.allocator);
        if (is_pong) break;
    }

    var probe: [16]u8 = undefined;
    try testing.expectError(error.HeadersPending, s.readBody(&probe));

    // Tiny 256-byte FixedBufferAllocator suffices for headers + trailers, while
    // 36 KiB of body streams with zero arena allocations!
    var hdr_backing: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&hdr_backing);
    const ev_hdr = try s.readEvent(fba.allocator());
    try testing.expect(ev_hdr == .headers);
    const arena_used_after_hdr = fba.end_index;

    // Emit 2 × 16000 B DATA + 1 padded DATA (pad=10, 4000 B data => wire 4011 B) + trailers.
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(testing.allocator);
    var c1: [16000]u8 = undefined;
    for (&c1, 0..) |*b, idx| b.* = @truncate(idx *% 3 +% 1);
    try expected.appendSlice(testing.allocator, &c1);
    try expected.appendSlice(testing.allocator, &c1);
    try ctWrite(&sw.interface, .data, 0, s.id, &c1);
    try ctWrite(&sw.interface, .data, 0, s.id, &c1);

    var padded_wire: [1 + 4000 + 10]u8 = @splat(0);
    padded_wire[0] = 10;
    for (padded_wire[1..4001], 0..) |*b, idx| b.* = @truncate(idx +% 7);
    try expected.appendSlice(testing.allocator, padded_wire[1..4001]);
    try ctWrite(&sw.interface, .data, p2.flag_padded, s.id, &padded_wire);

    var tr_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer tr_arena.deinit();
    var tr_blk: std.ArrayList(u8) = .empty;
    try hpack.Encoder.encodeTrailers(tr_arena.allocator(), &tr_blk, &.{.{ .name = "grpc-status", .value = "0" }});
    try ctWrite(&sw.interface, .headers, p2.flag_end_headers | p2.flag_end_stream, s.id, tr_blk.items);

    const br = s.bodyReader();
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(testing.allocator);
    var odd_buf: [3333]u8 = undefined;
    while (true) {
        const n = try br.read(&odd_buf);
        if (n == 0) break;
        try received.appendSlice(testing.allocator, odd_buf[0..n]);
    }
    try testing.expectEqual(arena_used_after_hdr, fba.end_index);
    try testing.expectEqualSlices(u8, expected.items, received.items);

    // Trailing HEADERS remain intact and readable via readEvent.
    const ev_tr = try s.readEvent(fba.allocator());
    try testing.expect(ev_tr == .headers);
    try testing.expect(ev_tr.headers.end_stream);
    try testing.expectEqualStrings("grpc-status", ev_tr.headers.headers[0].name);
    try testing.expectEqualStrings("0", ev_tr.headers.headers[0].value);

    // Total wire DATA cost = 16000 + 16000 + 4011 = 36011 B -> must be replenished in full on stream 0.
    try ctWrite(&sw.interface, .ping, 0, 0, &ping);
    var conn_wu: u32 = 0;
    while (true) {
        var f = try ctRead(testing.allocator, &sr.interface);
        defer f.deinit(testing.allocator);
        if (f.hdr.ftype == .window_update and f.hdr.sid == 0) {
            conn_wu += std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
        }
        if (f.hdr.ftype == .ping and (f.hdr.flags & p2.flag_ack != 0)) break;
    }
    try testing.expectEqual(@as(u32, 36011), conn_wu);
}

test "Client enforces write_timeout_ms on stalled writes and supports non-blocking control piggybacking" {
    // Part A: control frame piggybacks onto ctrl_buf without blocking when write_mu is held.
    {
        const Sink = struct {
            bytes: std.ArrayList(u8) = .empty,
            writer: Io.Writer,
            fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
                const self: *@This() = @fieldParentPtr("writer", w);
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
                return total;
            }
        };
        var wbuf: [4096]u8 = undefined;
        var sink: Sink = .{ .writer = .{ .buffer = &wbuf, .vtable = &.{ .drain = Sink.drain } } };
        defer sink.bytes.deinit(testing.allocator);
        var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };
        var client: Client = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .r = &dummy_r,
            .w = &sink.writer,
            .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        };
        defer client.deinit();

        const Holder = struct {
            c: *Client,
            locked: std.atomic.Value(bool) = .init(false),
            fn run(self: *@This()) void {
                self.c.write_mu.lockUncancelable(testing.io);
                self.locked.store(true, .release);
                Io.sleep(testing.io, .{ .nanoseconds = 80 * std.time.ns_per_ms }, .awake) catch {};
                self.c.finishWriteAndUnlock(null, false) catch {};
            }
        };
        var holder: Holder = .{ .c = &client };
        const th = try std.Thread.spawn(.{}, Holder.run, .{&holder});
        while (!holder.locked.load(.acquire)) {
            Io.sleep(testing.io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
        }

        const t0 = Io.Timestamp.now(testing.io, .awake).nanoseconds;
        const pong: [8]u8 = @splat(0x99);
        try client.writeFrame(.ping, p2.flag_ack, 0, &pong);
        const enqueue_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - t0, std.time.ns_per_ms);
        try testing.expect(enqueue_ms < 50);

        th.join();
        try testing.expectEqual(@as(usize, 17), sink.bytes.items.len);
    }

    // Part B: write_timeout_ms aborts stalled handshake/frame flush.
    {
        const StallSink = struct {
            writer: Io.Writer,
            fn drain(_: *Io.Writer, _: []const []const u8, _: usize) Io.Writer.Error!usize {
                Io.sleep(testing.io, .{ .nanoseconds = 5 * std.time.ns_per_s }, .awake) catch return error.WriteFailed;
                return error.WriteFailed;
            }
        };
        var ss: StallSink = .{ .writer = .{ .buffer = &.{}, .vtable = &.{ .drain = StallSink.drain } } };
        var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };
        var client: Client = undefined;
        const t0 = Io.Timestamp.now(testing.io, .awake).nanoseconds;
        try testing.expectError(error.Timeout, client.initWithConfig(testing.io, testing.allocator, &dummy_r, &ss.writer, .{
            .write_timeout_ms = 50,
        }));
        const elapsed_ms = @divFloor(Io.Timestamp.now(testing.io, .awake).nanoseconds - t0, std.time.ns_per_ms);
        try testing.expect(elapsed_ms < 1_000);
    }
}

test "Client.deinit never hangs when Io.Group readerLoop exits immediately on instant EOF (#49)" {
    const NoopSink = struct {
        writer: Io.Writer,
        fn drain(w: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
            w.end = 0;
            return data[0].len;
        }
    };

    for (0..40) |i| {
        var er: Io.Reader = .fixed(&.{});
        var wbuf: [256]u8 = undefined;
        var ns: NoopSink = .{ .writer = .{ .buffer = &wbuf, .vtable = &.{ .drain = NoopSink.drain } } };
        var client: Client = undefined;
        try client.init(testing.io, testing.allocator, &er, &ns.writer);
        if (i % 2 == 0) {
            Io.sleep(testing.io, .{ .nanoseconds = 200 * std.time.ns_per_us }, .awake) catch {};
        }
        client.deinit();
    }
}

test "Client.writeWindowUpdates tears down connection on ctrl_buf OOM instead of dropping credit (#49)" {
    const NoopSink = struct {
        writer: Io.Writer,
        fn drain(_: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
            return data[0].len;
        }
    };
    var ns: NoopSink = .{ .writer = .{ .buffer = &.{}, .vtable = &.{ .drain = NoopSink.drain } } };
    var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };
    var client: Client = .{
        .io = testing.io,
        .gpa = testing.failing_allocator,
        .r = &dummy_r,
        .w = &ns.writer,
        .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
    };
    client.reader_group_started.store(true, .release);
    client.reader_done.set(testing.io);
    defer client.deinit();

    const Holder = struct {
        c: *Client,
        locked: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.c.write_mu.lockUncancelable(testing.io);
            self.locked.store(true, .release);
            while (!self.release.load(.acquire)) {
                Io.sleep(testing.io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
            }
            self.c.finishWriteAndUnlock(null, true) catch |e| {
                self.err = e;
            };
        }
    };
    var h: Holder = .{ .c = &client };
    const th = try std.Thread.spawn(.{}, Holder.run, .{&h});
    while (!h.locked.load(.acquire)) {
        Io.sleep(testing.io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
    }

    client.writeWindowUpdates(4096, 1, 4096);
    try testing.expect(client.dead.load(.acquire));

    h.release.store(true, .release);
    th.join();
    try testing.expectEqual(@as(?anyerror, error.WriteFailed), h.err);
    try testing.expect(client.write_broken);
}

test "client stateful HPACK EncoderContext compresses repeated origin headers and guards HeadersTooLarge" {
    const CountingWriter = struct {
        writer: Io.Writer,
        bytes: std.ArrayList(u8) = .empty,
        fn drain(w: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", w);
            if (w.end > 0) {
                self.bytes.appendSlice(testing.allocator, w.buffer[0..w.end]) catch return error.WriteFailed;
                w.end = 0;
            }
            for (data) |s| {
                if (s.len > 0) self.bytes.appendSlice(testing.allocator, s) catch return error.WriteFailed;
            }
            return data[0].len;
        }
    };

    var wbuf: [4096]u8 = undefined;
    var cw: CountingWriter = .{ .writer = .{ .buffer = &wbuf, .vtable = &.{ .drain = CountingWriter.drain } } };
    defer cw.bytes.deinit(testing.allocator);
    var dummy_r: Io.Reader = .{ .buffer = &.{}, .seek = 0, .end = 0, .vtable = undefined };
    var client: Client = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .r = &dummy_r,
        .w = &cw.writer,
        .dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size),
        .enc = hpack.EncoderContext.initWithMaxSize(4096),
    };
    defer client.deinit();

    // Oversized header set (> 256 KiB) must return `HeadersTooLarge` WITHOUT mutating `client.enc.dyn`.
    const huge_val = try testing.allocator.alloc(u8, 300_000);
    defer testing.allocator.free(huge_val);
    @memset(huge_val, 'q');
    try testing.expectError(error.HeadersTooLarge, client.openStream(.{
        .method = "GET",
        .path = "/oversized",
        .authority = "origin.cdn.internal",
        .headers = &.{
            .{ .name = "x-seed-check", .value = "must-not-stick" },
            .{ .name = "x-giant", .value = huge_val },
        },
    }, true));
    try testing.expectEqual(@as(usize, 0), client.enc.dyn.len());

    const origin_headers = [_]Header{
        .{ .name = "user-agent", .value = "zig-cdn-origin-fetcher/2.0" },
        .{ .name = "x-cdn-pop", .value = "fra-02" },
        .{ .name = "authorization", .value = "Bearer origin-secret" },
    };

    const s1 = try client.openStream(.{
        .method = "GET",
        .path = "/asset-1.bin",
        .authority = "origin.cdn.internal",
        .headers = &origin_headers,
    }, true);
    defer s1.close();
    const first_wire_len = cw.bytes.items.len;

    const s2 = try client.openStream(.{
        .method = "GET",
        .path = "/asset-2.bin",
        .authority = "origin.cdn.internal",
        .headers = &origin_headers,
    }, true);
    defer s2.close();
    const second_wire_len = cw.bytes.items.len - first_wire_len;
    try testing.expect(second_wire_len < first_wire_len);

    // Decode both emitted HEADERS frames in wire order and verify all fields.
    var dec = hpack.Decoder.init(testing.allocator, p2.our_header_table_size);
    defer dec.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var pos: usize = 0;
    var count: usize = 0;
    while (pos < cw.bytes.items.len) {
        const fh = p2.parseHeader(cw.bytes.items[pos..][0..9]);
        pos += 9;
        const hs = try dec.decode(arena_state.allocator(), cw.bytes.items[pos .. pos + fh.length]);
        pos += fh.length;
        count += 1;
        var saw_auth = false;
        var saw_pop = false;
        for (hs) |h| {
            if (std.mem.eql(u8, h.name, "authorization") and std.mem.eql(u8, h.value, "Bearer origin-secret")) saw_auth = true;
            if (std.mem.eql(u8, h.name, "x-cdn-pop") and std.mem.eql(u8, h.value, "fra-02")) saw_pop = true;
        }
        try testing.expect(saw_auth and saw_pop);
    }
    try testing.expectEqual(@as(usize, 2), count);
}

test "client lock-free op_state drains concurrent operations cleanly on deinit" {
    const NoopSink = struct {
        writer: Io.Writer,
        fn drain(w: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
            w.end = 0;
            return data[0].len;
        }
    };
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
    var ns: NoopSink = .{ .writer = .{ .buffer = &cwbuf, .vtable = &.{ .drain = NoopSink.drain } } };
    var client: Client = undefined;
    try client.init(io, testing.allocator, &csr.interface, &ns.writer);

    const s1 = try client.openStream(.{ .method = "POST", .path = "/hold1" }, false);
    const s2 = try client.openStream(.{ .method = "POST", .path = "/hold2" }, false);

    const ReaderWorker = struct {
        s: *Stream,
        entered: std.atomic.Value(bool) = .init(false),
        fn run(self: *@This()) void {
            var buf: [64]u8 = undefined;
            self.entered.store(true, .release);
            _ = self.s.readBody(&buf) catch {};
        }
    };
    var w1: ReaderWorker = .{ .s = s1 };
    var w2: ReaderWorker = .{ .s = s2 };
    const t1 = try std.Thread.spawn(.{}, ReaderWorker.run, .{&w1});
    const t2 = try std.Thread.spawn(.{}, ReaderWorker.run, .{&w2});
    while (!w1.entered.load(.acquire) or !w2.entered.load(.acquire)) {
        Io.sleep(io, .{ .nanoseconds = 1 * std.time.ns_per_ms }, .awake) catch {};
    }
    Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};

    // `deinit` must wake both in-flight `readBody` callers, wait on `op_state`
    // futex until both call `endOp()`, seal `op_sealed_bit`, and free streams.
    client.deinit();
    t1.join();
    t2.join();
    try testing.expect(client.isSealed());
}
