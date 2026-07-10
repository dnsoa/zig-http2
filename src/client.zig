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
const Queued = union(enum) {
    headers: []const Header,
    data: []u8,
};

/// How often the reader's blocking read wakes when no keepalive is configured,
/// so `deinit` (which sets `dead`) stops the reader within this window.
const reader_wake_ms: u64 = 50;

pub const Stream = struct {
    client: *Client,
    id: u31,
    /// Flow-control window for DATA we send, guarded by `client.send_mu`.
    send_window: i64,

    recv_mu: Io.Mutex = .init,
    recv_cond: Io.Condition = .init,
    queue: std.ArrayList(Queued) = .empty,
    /// end_stream flags for the queued items — tracked alongside so a queued
    /// DATA/HEADERS can report whether it closes the stream.
    end_flags: std.ArrayList(bool) = .empty,
    is_headers: std.ArrayList(bool) = .empty,
    reset: ?u32 = null,
    rst_delivered: bool = false,
    remote_closed: bool = false,

    /// Sends `data` as flow-controlled DATA frames; `end_stream` half-closes.
    /// Blocks while the send window is empty; errors on reset/teardown.
    pub fn send(self: *Stream, data: []const u8, end_stream: bool) !void {
        const c = self.client;
        if (data.len == 0) {
            if (end_stream) try c.writeData(self.id, "", true);
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
                if (self.send_window <= 0) {
                    c.send_cond.waitUncancelable(c.io, &c.send_mu);
                    continue;
                }
                const avail = @min(self.send_window, c.conn_send_window);
                if (avail <= 0) {
                    c.send_cond.waitUncancelable(c.io, &c.send_mu);
                    continue;
                }
                const want: i64 = @min(@as(i64, @intCast(data.len - off)), @min(avail, @as(i64, @intCast(c.peer_max_frame))));
                self.send_window -= want;
                c.conn_send_window -= want;
                break :blk @as(usize, @intCast(want));
            };
            c.send_mu.unlock(c.io);
            const last = off + n == data.len;
            try c.writeData(self.id, data[off .. off + n], end_stream and last);
            off += n;
        }
    }

    /// Reads the next event on this stream, blocking until one is available.
    /// Decoded headers / copied DATA are owned by `arena`. Returns
    /// `error.EndOfStream` once the peer has half-closed and the queue drains,
    /// `error.ConnectionClosed` when the connection tears down.
    pub fn readEvent(self: *Stream, arena: std.mem.Allocator) !Event {
        const c = self.client;
        self.recv_mu.lockUncancelable(c.io);
        defer self.recv_mu.unlock(c.io);
        while (true) {
            if (self.queue.items.len > 0) {
                const bytes = self.queue.orderedRemove(0);
                const end_stream = self.end_flags.orderedRemove(0);
                const is_hdr = self.is_headers.orderedRemove(0);
                if (is_hdr) {
                    const hs = bytes.headers;
                    const out = try arena.alloc(Header, hs.len);
                    for (hs, 0..) |h, i| {
                        out[i] = .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) };
                    }
                    freeHeaders(c.gpa, hs);
                    return .{ .headers = .{ .sid = self.id, .headers = out, .end_stream = end_stream } };
                } else {
                    const out = try arena.dupe(u8, bytes.data);
                    c.gpa.free(bytes.data);
                    return .{ .data = .{ .sid = self.id, .payload = out, .end_stream = end_stream } };
                }
            }
            if (self.reset != null and !self.rst_delivered) {
                self.rst_delivered = true;
                return .{ .rst = .{ .sid = self.id, .code = self.reset.? } };
            }
            if (c.dead.load(.acquire)) return error.ConnectionClosed;
            if (self.remote_closed) return error.EndOfStream;
            self.recv_cond.waitUncancelable(c.io, &self.recv_mu);
        }
    }

    /// Cancels the stream: sends RST_STREAM(CANCEL). Stop using the stream
    /// afterwards (the peer tears down its half).
    pub fn cancel(self: *Stream) !void {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, @intFromEnum(p2.ErrorCode.cancel), .big);
        try self.client.writeFrame(.rst_stream, 0, self.id, &p);
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
        const ended = self.remote_closed or self.reset != null;
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

    /// Frees everything still buffered on this stream.
    fn freeQueued(self: *Stream, gpa: std.mem.Allocator) void {
        for (self.queue.items, self.is_headers.items) |item, is_hdr| {
            if (is_hdr) freeHeaders(gpa, item.headers) else gpa.free(item.data);
        }
        self.queue.deinit(gpa);
        self.end_flags.deinit(gpa);
        self.is_headers.deinit(gpa);
    }
};

pub const Client = struct {
    io: Io,
    gpa: std.mem.Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    dec: hpack.Decoder,
    next_id: u31 = 1,
    peer_max_frame: u32 = 16384,
    peer_initial_window: u32 = @intCast(p2.default_window),

    write_mu: Io.Mutex = .init,

    // Send-side flow control (connection + per-stream windows live here).
    send_mu: Io.Mutex = .init,
    send_cond: Io.Condition = .init,
    conn_send_window: i64 = p2.default_window,

    streams_mu: Io.Mutex = .init,
    streams: std.AutoHashMapUnmanaged(u31, *Stream) = .empty,

    keepalive_time_ms: u64 = 0,
    keepalive_timeout_ms: u64 = 0,
    ping_outstanding: bool = false,

    dead: std.atomic.Value(bool) = .init(false),
    reader_thread: ?std.Thread = null,

    const TimedHeader = union(enum) { work: anyerror!void, timer: void };

    /// Sends the connection preface + empty SETTINGS and starts the reader.
    /// Takes `self` by pointer so the reader thread has a stable address.
    pub fn init(self: *Client, io: Io, gpa: std.mem.Allocator, r: *Io.Reader, w: *Io.Writer) !void {
        self.* = .{
            .io = io,
            .gpa = gpa,
            .r = r,
            .w = w,
            .dec = hpack.Decoder.init(gpa, p2.our_header_table_size),
        };
        try self.w.writeAll(p2.preface);
        // Advertise SETTINGS_ENABLE_PUSH=0. We do not implement PUSH_PROMISE
        // (and never decode its header block), so a push would desync the HPACK
        // decoder for the whole connection — disable it up front.
        var settings: [6]u8 = undefined;
        p2.putSetting(&settings, p2.set_enable_push, 0);
        try self.writeFrame(.settings, 0, 0, &settings);
        self.reader_thread = std.Thread.spawn(.{}, readerLoop, .{self}) catch null;
    }

    pub fn deinit(self: *Client) void {
        // Tell the reader to stop, then wake any blocked senders/readers so they
        // observe `dead` and return. The reader wakes within `reader_wake_ms`.
        self.dead.store(true, .release);
        self.send_cond.broadcast(self.io);
        self.streams_mu.lockUncancelable(self.io);
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.*.shutdown(self.io);
        self.streams_mu.unlock(self.io);
        if (self.reader_thread) |t| t.join();

        self.dec.deinit();
        var it2 = self.streams.valueIterator();
        while (it2.next()) |s| {
            s.*.freeQueued(self.gpa);
            self.gpa.destroy(s.*);
        }
        self.streams.deinit(self.gpa);
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

    /// Opens a new stream, sending the request HEADERS. Returns a handle for
    /// send/readEvent/cancel. `end_stream` half-closes immediately (bodyless).
    /// The stream id is allocated and HEADERS emitted under `write_mu` so that
    /// concurrent openers issue ids in strictly increasing wire order (RFC 7540
    /// §5.1.1); the stream is registered before HEADERS is sent so the reader
    /// can deliver the response.
    pub fn openStream(self: *Client, head: RequestHead, end_stream: bool) !*Stream {
        if (self.dead.load(.acquire)) return error.ConnectionClosed;

        var tmp = std.heap.ArenaAllocator.init(self.gpa);
        defer tmp.deinit();
        var block: std.ArrayList(u8) = .empty;
        try hpack.Encoder.encodeRequest(tmp.allocator(), &block, head.method, head.scheme, head.path, head.authority, head.headers);

        self.write_mu.lockUncancelable(self.io);
        const sid = self.next_id;
        self.next_id = std.math.add(u31, sid, 2) catch {
            self.write_mu.unlock(self.io);
            return error.StreamIdsExhausted;
        };

        const st = self.gpa.create(Stream) catch {
            self.write_mu.unlock(self.io);
            return error.OutOfMemory;
        };
        st.* = .{ .client = self, .id = sid, .send_window = self.peer_initial_window };
        self.streams_mu.lockUncancelable(self.io);
        self.streams.put(self.gpa, sid, st) catch {
            self.streams_mu.unlock(self.io);
            self.write_mu.unlock(self.io);
            self.gpa.destroy(st);
            return error.OutOfMemory;
        };
        self.streams_mu.unlock(self.io);

        const flags: u8 = p2.flag_end_headers | (if (end_stream) p2.flag_end_stream else 0);
        self.writeFrameLocked(.headers, flags, sid, block.items) catch {
            self.write_mu.unlock(self.io);
            self.removeStream(sid);
            return error.ConnectionClosed;
        };
        self.w.flush() catch {
            self.write_mu.unlock(self.io);
            self.removeStream(sid);
            return error.ConnectionClosed;
        };
        self.write_mu.unlock(self.io);
        return st;
    }

    fn removeStream(self: *Client, sid: u31) void {
        self.streams_mu.lockUncancelable(self.io);
        if (self.streams.fetchRemove(sid)) |kv| {
            self.streams_mu.unlock(self.io);
            kv.value.freeQueued(self.gpa);
            self.gpa.destroy(kv.value);
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
        self.streams_mu.lockUncancelable(self.io);
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.*.shutdown(self.io);
        self.streams_mu.unlock(self.io);
    }

    fn handle(self: *Client, fh: p2.ParsedHeader, payload: []const u8) !void {
        switch (fh.ftype) {
            .settings => if (fh.flags & p2.flag_ack == 0) {
                self.applyPeerSettings(payload);
                try self.writeFrame(.settings, p2.flag_ack, 0, "");
            },
            .ping => if (fh.flags & p2.flag_ack == 0) try self.writeFrame(.ping, p2.flag_ack, 0, payload),
            .window_update => try self.handleWindowUpdate(fh.sid, payload),
            .goaway => {
                self.kill();
                return error.ConnectionClosed;
            },
            .rst_stream => {
                const code: u32 = if (payload.len >= 4) std.mem.readInt(u32, payload[0..4], .big) else 0;
                self.streams_mu.lockUncancelable(self.io);
                if (self.streams.get(fh.sid)) |st| {
                    st.recv_mu.lockUncancelable(self.io);
                    st.reset = code;
                    st.recv_cond.broadcast(self.io);
                    st.recv_mu.unlock(self.io);
                }
                self.streams_mu.unlock(self.io);
            },
            .headers => {
                var block: std.ArrayList(u8) = .empty;
                defer block.deinit(self.gpa);
                try block.appendSlice(self.gpa, stripHeaderPadding(fh, payload));
                if (fh.flags & p2.flag_end_headers == 0) try self.readContinuations(fh.sid, &block);
                const hs = try self.dec.decode(self.gpa, block.items);
                try self.deliver(fh.sid, true, hs, &[_]u8{}, fh.flags & p2.flag_end_stream != 0);
            },
            .data => {
                if (payload.len > 0) self.replenish(fh.sid, @intCast(payload.len));
                const copy = try self.gpa.dupe(u8, payload);
                try self.deliver(fh.sid, false, &[_]hpack.Header{}, copy, fh.flags & p2.flag_end_stream != 0);
            },
            .push_promise => {
                // We advertised ENABLE_PUSH=0, so a push is a protocol
                // violation. Tolerating it is also unsafe: its header block goes
                // undecoded, desyncing HPACK for every later frame. Tear down.
                self.kill();
                return error.ConnectionClosed;
            },
            else => {}, // priority / stray continuation
        }
    }

    /// Pushes one item onto the stream's queue (or frees it if the stream is
    /// gone). Lock order: streams_mu -> recv_mu.
    fn deliver(self: *Client, sid: u31, is_headers: bool, hs: []const Header, bytes: []u8, end_stream: bool) !void {
        self.streams_mu.lockUncancelable(self.io);
        const st = self.streams.get(sid);
        if (st) |s| {
            s.recv_mu.lockUncancelable(self.io);
            const item: Queued = if (is_headers) .{ .headers = hs } else .{ .data = bytes };
            s.queue.append(self.gpa, item) catch {
                s.recv_mu.unlock(self.io);
                self.streams_mu.unlock(self.io);
                if (is_headers) freeHeaders(self.gpa, hs) else self.gpa.free(bytes);
                return error.OutOfMemory;
            };
            s.end_flags.append(self.gpa, end_stream) catch {
                s.queue.items.len -= 1;
                s.recv_mu.unlock(self.io);
                self.streams_mu.unlock(self.io);
                if (is_headers) freeHeaders(self.gpa, hs) else self.gpa.free(bytes);
                return error.OutOfMemory;
            };
            s.is_headers.append(self.gpa, is_headers) catch {
                s.queue.items.len -= 1;
                s.end_flags.items.len -= 1;
                s.recv_mu.unlock(self.io);
                self.streams_mu.unlock(self.io);
                if (is_headers) freeHeaders(self.gpa, hs) else self.gpa.free(bytes);
                return error.OutOfMemory;
            };
            if (end_stream) s.remote_closed = true;
            s.recv_cond.broadcast(self.io);
            s.recv_mu.unlock(self.io);
            self.streams_mu.unlock(self.io);
        } else {
            self.streams_mu.unlock(self.io);
            if (is_headers) freeHeaders(self.gpa, hs) else self.gpa.free(bytes);
        }
    }

    /// Credits the peer's send windows for `amt` bytes of DATA we received.
    fn replenish(self: *Client, sid: u31, amt: u31) void {
        var wu: [4]u8 = undefined;
        std.mem.writeInt(u32, &wu, @as(u32, amt), .big);
        self.writeFrame(.window_update, 0, 0, &wu) catch {};
        self.writeFrame(.window_update, 0, sid, &wu) catch {};
    }

    fn handleWindowUpdate(self: *Client, sid: u31, payload: []const u8) !void {
        if (payload.len < 4) return;
        const incr: i64 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
        if (incr == 0) return error.ProtocolError;
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
                st.send_window = 0;
                var p: [4]u8 = undefined;
                std.mem.writeInt(u32, &p, @intFromEnum(p2.ErrorCode.flow_control_error), .big);
                self.writeFrame(.rst_stream, 0, sid, &p) catch {};
            } else {
                st.send_window += incr;
            }
        }
        self.send_cond.broadcast(self.io);
    }

    fn applyPeerSettings(self: *Client, payload: []const u8) void {
        var i: usize = 0;
        var new_iw: ?u32 = null;
        while (i + 6 <= payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            switch (id) {
                p2.set_max_frame_size => if (val >= 16384 and val <= 16777215) {
                    self.peer_max_frame = val;
                },
                p2.set_initial_window_size => {
                    if (val > 0x7fff_ffff) {
                        self.kill();
                        return;
                    }
                    new_iw = val;
                },
                else => {},
            }
        }
        if (new_iw) |iw| self.applyInitialWindow(iw);
    }

    /// Shift every live stream's send window by the SETTINGS_INITIAL_WINDOW_SIZE
    /// delta (RFC 7540 §6.9.2). Lock order: streams_mu -> send_mu.
    fn applyInitialWindow(self: *Client, new_iw: u32) void {
        self.streams_mu.lockUncancelable(self.io);
        defer self.streams_mu.unlock(self.io);
        self.send_mu.lockUncancelable(self.io);
        defer self.send_mu.unlock(self.io);
        const delta: i64 = @as(i64, new_iw) - @as(i64, self.peer_initial_window);
        self.peer_initial_window = new_iw;
        if (delta == 0) return;
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.*.send_window += delta;
        self.send_cond.broadcast(self.io);
    }

    fn readContinuations(self: *Client, sid: u31, block: *std.ArrayList(u8)) !void {
        while (true) {
            var hb: [9]u8 = undefined;
            try self.r.readSliceAll(&hb);
            const cf = p2.parseHeader(&hb);
            if (cf.ftype != .continuation or cf.sid != sid) return error.ProtocolError;
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
                    const ping = [_]u8{0} ** 8;
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

/// HEADERS frames may carry PADDED/PRIORITY prefixes; strip them for decoding.
fn stripHeaderPadding(fh: p2.ParsedHeader, payload: []const u8) []const u8 {
    var frag = payload;
    if (fh.flags & p2.flag_padded != 0) {
        if (frag.len == 0) return frag;
        const pad = frag[0];
        frag = frag[1..];
        if (pad <= frag.len) frag = frag[0 .. frag.len - pad];
    }
    if (fh.flags & p2.flag_priority != 0 and frag.len >= 5) frag = frag[5..];
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
