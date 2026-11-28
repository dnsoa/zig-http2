//! Shared serialized HTTP/2 outbound frame writer (`FrameWriter`), unifying
//! connection-stateful HPACK encoding, vectored frame emission, outbound write
//! deadlines (`write_timeout_ms`), and the non-blocking high-priority control
//! piggyback queue (`ctrl_buf`) across both `Server` and `Client`.
//!
//! Lock hierarchy: `mu -> ctrl_mu` (or `ctrl_mu` standalone when `mu.tryLock()`
//! misses). `finishAndUnlock` performs hand-over-hand unlocking of `mu` while
//! holding `ctrl_mu` so no queued control frame is ever stranded idle.

const std = @import("std");
const Io = std.Io;
const proto = @import("proto.zig");
const hpack = @import("hpack.zig");

pub const HtsUpdate = struct {
    min: u32,
    last: u32,
};

pub const FrameWriter = struct {
    io: Io,
    w: *Io.Writer,
    gpa: ?std.mem.Allocator = null,
    write_timeout_ms: u64 = 0,
    on_broken_ctx: ?*anyopaque = null,
    on_broken_fn: ?*const fn (ctx: *anyopaque) void = null,

    mu: Io.Mutex = .init,
    /// Poisoned on any write/flush failure or timeout so concurrent writers
    /// never emit misaligned frames after a partial frame landed on the wire.
    broken: bool = false,
    /// Outbound connection-stateful HPACK encoder & reusable scratch buffer,
    /// mutated strictly under `mu` in exact on-wire `HEADERS` emission order.
    enc: hpack.EncoderContext = .{},
    hpack_buf: std.ArrayList(u8) = .empty,

    /// High-priority non-blocking control-frame queue (`PING ACK`, `SETTINGS ACK`,
    /// `WINDOW_UPDATE`, `RST_STREAM`, `GOAWAY`, `PRIORITY_UPDATE`).
    ctrl_mu: Io.Mutex = .init,
    ctrl_buf: std.ArrayList(u8) = .empty,
    ctrl_drain: std.ArrayList(u8) = .empty,
    ctrl_hts_min: ?u32 = null,
    ctrl_hts_last: ?u32 = null,
    ctrl_broken: bool = false,

    pub fn deinitWithAllocator(self: *FrameWriter, fallback_gpa: std.mem.Allocator) void {
        const alloc = self.gpa orelse fallback_gpa;
        self.ctrl_buf.deinit(alloc);
        self.ctrl_drain.deinit(alloc);
        self.hpack_buf.deinit(alloc);
        self.enc.deinit(alloc);
    }

    pub fn deinit(self: *FrameWriter) void {
        if (self.gpa) |gpa| {
            self.deinitWithAllocator(gpa);
        }
    }

    pub fn lock(self: *FrameWriter) void {
        self.mu.lockUncancelable(self.io);
    }

    pub fn unlock(self: *FrameWriter) void {
        self.mu.unlock(self.io);
    }

    inline fn notifyBroken(self: *FrameWriter, fire_callback: bool) void {
        if (fire_callback) {
            if (self.on_broken_fn) |cb| cb(self.on_broken_ctx.?);
        }
    }

    pub fn markBrokenLocked(self: *FrameWriter, fire_callback: bool) void {
        self.broken = true;
        self.ctrl_mu.lockUncancelable(self.io);
        self.ctrl_broken = true;
        self.ctrl_buf.clearRetainingCapacity();
        self.ctrl_hts_min = null;
        self.ctrl_hts_last = null;
        self.ctrl_mu.unlock(self.io);
        self.notifyBroken(fire_callback);
    }

    /// Marks the control queue broken on an OOM while `ctrl_mu` is held
    /// (without `mu`), invokes `on_broken_fn` if `fire_callback`, and syncs
    /// `self.broken = true` if `mu` is already free.
    pub fn failCtrlAllocAndUnlock(self: *FrameWriter, fire_callback: bool) void {
        self.ctrl_broken = true;
        self.ctrl_buf.clearRetainingCapacity();
        self.ctrl_hts_min = null;
        self.ctrl_hts_last = null;
        self.ctrl_mu.unlock(self.io);
        self.notifyBroken(fire_callback);
        if (self.mu.tryLock()) {
            self.broken = true;
            self.unlock();
        }
    }

    /// Writes one frame; assumes `mu` is held. Uses `writeVecAll` to submit the
    /// 9-byte header and payload together without splitting `drain` calls.
    pub fn frameLocked(
        self: *FrameWriter,
        ftype: proto.FrameType,
        flags: u8,
        sid: u31,
        payload: []const u8,
    ) !void {
        var hdr: [9]u8 = undefined;
        proto.putHeader(&hdr, payload.len, ftype, flags, sid);
        if (payload.len > 0) {
            var vecs = [_][]const u8{ &hdr, payload };
            try self.w.writeVecAll(&vecs);
        } else {
            try self.w.writeAll(&hdr);
        }
    }

    /// Writes `data` as one or more `DATA` frames (`<= max_frame`) without flushing.
    /// Caller holds `mu`.
    pub fn writeDataFramesLocked(
        self: *FrameWriter,
        sid: u31,
        data: []const u8,
        end_stream: bool,
        max_frame: usize,
    ) !void {
        std.debug.assert(max_frame > 0);
        if (data.len == 0) {
            if (end_stream) try self.frameLocked(.data, proto.flag_end_stream, sid, "");
            return;
        }
        var off: usize = 0;
        while (off < data.len) {
            const chunk_len = @min(data.len - off, max_frame);
            const is_last = off + chunk_len == data.len;
            const flags: u8 = if (end_stream and is_last) proto.flag_end_stream else 0;
            try self.frameLocked(.data, flags, sid, data[off .. off + chunk_len]);
            off += chunk_len;
        }
    }

    /// Writes `byte_count` bytes starting at `slices[start_idx.*][start_off.*]` as
    /// `DATA` frames (`<= max_frame`) without copying into an intermediate buffer,
    /// advancing `start_idx` and `start_off`. Caller holds `mu`.
    pub fn writeDataVecWindowLocked(
        self: *FrameWriter,
        sid: u31,
        slices: []const []const u8,
        start_idx: *usize,
        start_off: *usize,
        byte_count: usize,
        end_stream: bool,
        max_frame: usize,
    ) !void {
        std.debug.assert(max_frame > 0);
        if (byte_count == 0) {
            if (end_stream) try self.frameLocked(.data, proto.flag_end_stream, sid, "");
            return;
        }

        var rem_total = byte_count;
        var s_idx = start_idx.*;
        var s_off = start_off.*;
        while (rem_total > 0) {
            while (s_idx < slices.len and s_off == slices[s_idx].len) {
                s_idx += 1;
                s_off = 0;
            }
            const frame_len = @min(rem_total, max_frame);
            const is_last = frame_len == rem_total;
            const flags: u8 = if (end_stream and is_last) proto.flag_end_stream else 0;
            const cur = slices[s_idx][s_off..];
            if (cur.len >= frame_len) {
                try self.frameLocked(.data, flags, sid, cur[0..frame_len]);
                s_off += frame_len;
            } else {
                var hdr: [9]u8 = undefined;
                proto.putHeader(&hdr, frame_len, .data, flags, sid);
                try self.w.writeAll(&hdr);
                var need = frame_len;
                while (need > 0) {
                    while (s_off == slices[s_idx].len) {
                        s_idx += 1;
                        s_off = 0;
                    }
                    const avail = slices[s_idx][s_off..];
                    const take = @min(need, avail.len);
                    try self.w.writeAll(avail[0..take]);
                    s_off += take;
                    need -= take;
                }
            }
            rem_total -= frame_len;
        }
        start_idx.* = s_idx;
        start_off.* = s_off;
    }

    /// Writes scatter-gather `slices` as `DATA` frames (`<= max_frame`) without
    /// allocating or copying into an intermediate contiguous buffer. Caller holds `mu`.
    pub fn writeDataVecLocked(
        self: *FrameWriter,
        sid: u31,
        slices: []const []const u8,
        end_stream: bool,
        max_frame: usize,
    ) !void {
        var total: usize = 0;
        for (slices) |s| total += s.len;
        var idx: usize = 0;
        var off: usize = 0;
        return self.writeDataVecWindowLocked(sid, slices, &idx, &off, total, end_stream, max_frame);
    }

    pub fn writeHeaderBlockLocked(
        self: *FrameWriter,
        sid: u31,
        end_stream: bool,
        max_frame: usize,
        block: []const u8,
    ) !void {
        const es: u8 = if (end_stream) proto.flag_end_stream else 0;
        if (block.len <= max_frame) {
            try self.frameLocked(.headers, proto.flag_end_headers | es, sid, block);
        } else {
            try self.frameLocked(.headers, es, sid, block[0..max_frame]);
            var off: usize = max_frame;
            while (off < block.len) {
                const end = @min(off + max_frame, block.len);
                const last = end == block.len;
                try self.frameLocked(.continuation, if (last) proto.flag_end_headers else 0, sid, block[off..end]);
                off = end;
            }
        }
    }

    /// Moves any queued control frames into `self.w` without flushing yet.
    /// Caller holds `mu`.
    pub fn drainCtrlToBufferLocked(self: *FrameWriter) !void {
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

    /// Drains any control frames queued while `mu` was held, flushes them under
    /// `write_timeout_ms`, and releases `mu` under `ctrl_mu` (hand-over-hand unlock).
    pub fn finishAndUnlockEx(self: *FrameWriter, write_err: ?anyerror, fire_callback: bool) !void {
        if (write_err) |err| {
            self.markBrokenLocked(fire_callback);
            self.unlock();
            return err;
        }
        while (true) {
            self.ctrl_mu.lockUncancelable(self.io);
            if (self.ctrl_broken) {
                self.ctrl_mu.unlock(self.io);
                self.markBrokenLocked(fire_callback);
                self.unlock();
                return error.WriteFailed;
            }
            if (self.ctrl_buf.items.len == 0) {
                self.unlock();
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
            const err_opt: ?anyerror = if (proto.runTimed(self.io, self.write_timeout_ms, writeAndFlushCtrlSliceThunk, .{ self.w, self.ctrl_drain.items })) |_|
                null
            else |e|
                e;
            self.ctrl_drain.clearRetainingCapacity();
            if (err_opt) |err| {
                self.markBrokenLocked(fire_callback);
                self.unlock();
                return err;
            }
        }
    }

    pub fn finishAndUnlock(self: *FrameWriter, write_err: ?anyerror) !void {
        return self.finishAndUnlockEx(write_err, true);
    }

    fn flushOnlyThunk(self: *FrameWriter) anyerror!void {
        try self.drainCtrlToBufferLocked();
        try self.w.flush();
    }

    pub fn flush(self: *FrameWriter, fire_callback: bool) !void {
        self.lock();
        if (self.broken) {
            self.unlock();
            return error.WriteFailed;
        }
        const err_opt: ?anyerror = if (proto.runTimed(self.io, self.write_timeout_ms, flushOnlyThunk, .{self})) |_|
            null
        else |e|
            e;
        return self.finishAndUnlockEx(err_opt, fire_callback);
    }

    pub fn writeSingleFrameThunk(
        self: *FrameWriter,
        ftype: proto.FrameType,
        flags: u8,
        sid: u31,
        payload: []const u8,
    ) anyerror!void {
        try self.drainCtrlToBufferLocked();
        try self.frameLocked(ftype, flags, sid, payload);
        try self.drainCtrlToBufferLocked();
        try self.w.flush();
    }

    /// Non-blocking control-frame emission when `mu` is contended and `gpa` is
    /// configured; synchronous write + flush when `mu` is free.
    pub fn writeControlFrame(
        self: *FrameWriter,
        ftype: proto.FrameType,
        flags: u8,
        sid: u31,
        payload: []const u8,
        hts_update: ?HtsUpdate,
        fire_callback: bool,
    ) !void {
        if (self.mu.tryLock()) {
            if (self.broken) {
                self.unlock();
                return error.WriteFailed;
            }
            const err_opt: ?anyerror = if (proto.runTimed(self.io, self.write_timeout_ms, writeSingleFrameThunk, .{ self, ftype, flags, sid, payload })) |_|
                null
            else |e|
                e;
            if (err_opt == null) {
                if (hts_update) |u| self.enc.notePeerHeaderTableSize(u.min, u.last);
            }
            return self.finishAndUnlockEx(err_opt, fire_callback);
        }
        if (self.gpa) |gpa| {
            self.ctrl_mu.lockUncancelable(self.io);
            if (self.ctrl_broken) {
                self.ctrl_mu.unlock(self.io);
                return error.WriteFailed;
            }
            var hdr: [9]u8 = undefined;
            proto.putHeader(&hdr, payload.len, ftype, flags, sid);
            self.ctrl_buf.ensureUnusedCapacity(gpa, 9 + payload.len) catch |err| {
                self.failCtrlAllocAndUnlock(fire_callback);
                return err;
            };
            self.ctrl_buf.appendSliceAssumeCapacity(&hdr);
            if (payload.len > 0) self.ctrl_buf.appendSliceAssumeCapacity(payload);
            if (hts_update) |u| {
                self.ctrl_hts_min = if (self.ctrl_hts_min) |prev| @min(prev, u.min) else u.min;
                self.ctrl_hts_last = u.last;
            }
            self.ctrl_mu.unlock(self.io);

            if (self.mu.tryLock()) {
                if (self.broken) {
                    self.unlock();
                    return error.WriteFailed;
                }
                return self.finishAndUnlockEx(null, fire_callback);
            }
            return;
        }
        self.lock();
        if (self.broken) {
            self.unlock();
            return error.WriteFailed;
        }
        const err_opt: ?anyerror = if (proto.runTimed(self.io, self.write_timeout_ms, writeSingleFrameThunk, .{ self, ftype, flags, sid, payload })) |_|
            null
        else |e|
            e;
        if (err_opt == null) {
            if (hts_update) |u| self.enc.notePeerHeaderTableSize(u.min, u.last);
        }
        return self.finishAndUnlockEx(err_opt, fire_callback);
    }

    pub fn ackSettings(self: *FrameWriter, hts_update: ?HtsUpdate) !void {
        return self.writeControlFrame(.settings, proto.flag_ack, 0, "", hts_update, true);
    }

    pub fn frame(self: *FrameWriter, ftype: proto.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        return self.writeControlFrame(ftype, flags, sid, payload, null, true);
    }

    fn writeWindowUpdatesThunk(
        self: *FrameWriter,
        first_sid: u31,
        first_incr: u32,
        second_sid: u31,
        second_incr: u32,
    ) anyerror!void {
        try self.drainCtrlToBufferLocked();
        if (first_incr > 0) {
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, first_incr & 0x7fff_ffff, .big);
            try self.frameLocked(.window_update, 0, first_sid, &wu);
        }
        if (second_incr > 0) {
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, second_incr & 0x7fff_ffff, .big);
            try self.frameLocked(.window_update, 0, second_sid, &wu);
        }
        try self.drainCtrlToBufferLocked();
        try self.w.flush();
    }

    /// Coalesces up to two `WINDOW_UPDATE` frames (`(first_sid, first_incr)` then
    /// `(second_sid, second_incr)`) into one lock/flush or non-blocking `ctrl_buf` entry.
    pub fn writeWindowUpdatesOrdered(
        self: *FrameWriter,
        first_sid: u31,
        first_incr: u32,
        second_sid: u31,
        second_incr: u32,
        fire_callback: bool,
    ) void {
        if (first_incr == 0 and second_incr == 0) return;
        if (self.mu.tryLock()) {
            if (self.broken) {
                self.unlock();
                return;
            }
            const err_opt: ?anyerror = if (proto.runTimed(self.io, self.write_timeout_ms, writeWindowUpdatesThunk, .{ self, first_sid, first_incr, second_sid, second_incr })) |_|
                null
            else |e|
                e;
            self.finishAndUnlockEx(err_opt, fire_callback) catch {};
            return;
        }
        if (self.gpa) |gpa| {
            self.ctrl_mu.lockUncancelable(self.io);
            if (self.ctrl_broken) {
                self.ctrl_mu.unlock(self.io);
                return;
            }
            const count: usize = @as(usize, if (first_incr > 0) 13 else 0) + @as(usize, if (second_incr > 0) 13 else 0);
            self.ctrl_buf.ensureUnusedCapacity(gpa, count) catch {
                self.failCtrlAllocAndUnlock(fire_callback);
                return;
            };
            if (first_incr > 0) {
                var hdr: [9]u8 = undefined;
                var wu: [4]u8 = undefined;
                proto.putHeader(&hdr, 4, .window_update, 0, first_sid);
                std.mem.writeInt(u32, &wu, first_incr & 0x7fff_ffff, .big);
                self.ctrl_buf.appendSliceAssumeCapacity(&hdr);
                self.ctrl_buf.appendSliceAssumeCapacity(&wu);
            }
            if (second_incr > 0) {
                var hdr: [9]u8 = undefined;
                var wu: [4]u8 = undefined;
                proto.putHeader(&hdr, 4, .window_update, 0, second_sid);
                std.mem.writeInt(u32, &wu, second_incr & 0x7fff_ffff, .big);
                self.ctrl_buf.appendSliceAssumeCapacity(&hdr);
                self.ctrl_buf.appendSliceAssumeCapacity(&wu);
            }
            self.ctrl_mu.unlock(self.io);
            if (self.mu.tryLock()) {
                if (self.broken) {
                    self.unlock();
                    return;
                }
                self.finishAndUnlockEx(null, fire_callback) catch {};
            }
            return;
        }
        self.lock();
        if (self.broken) {
            self.unlock();
            return;
        }
        const err_opt: ?anyerror = if (proto.runTimed(self.io, self.write_timeout_ms, writeWindowUpdatesThunk, .{ self, first_sid, first_incr, second_sid, second_incr })) |_|
            null
        else |e|
            e;
        self.finishAndUnlockEx(err_opt, fire_callback) catch {};
    }

    /// Convenience wrapper emitting `(sid, stream_incr)` then `(0, conn_incr)`.
    pub fn writeWindowUpdates(self: *FrameWriter, sid: u31, stream_incr: i64, conn_incr: i64) void {
        const s_inc: u32 = if (stream_incr > 0) @intCast(stream_incr) else 0;
        const c_inc: u32 = if (conn_incr > 0) @intCast(conn_incr) else 0;
        self.writeWindowUpdatesOrdered(sid, s_inc, 0, c_inc, true);
    }
};

test "FrameWriter.writeDataVecLocked packs irregular scatter-gather slices into exact max_frame DATA frames" {
    const testing = std.testing;
    const WireSink = struct {
        bytes: std.ArrayList(u8) = .empty,
        writer: Io.Writer,
        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", w);
            if (w.end > 0) {
                self.bytes.appendSlice(testing.allocator, w.buffer[0..w.end]) catch return error.WriteFailed;
                w.end = 0;
            }
            var total: usize = 0;
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
    var sink_buf: [256]u8 = undefined;
    var sink: WireSink = .{ .writer = .{ .buffer = &sink_buf, .vtable = &.{ .drain = WireSink.drain } } };
    defer sink.bytes.deinit(testing.allocator);

    var fw: FrameWriter = .{
        .io = testing.io,
        .w = &sink.writer,
        .gpa = testing.allocator,
    };
    defer fw.deinitWithAllocator(testing.allocator);

    const s1 = "abc"; // 3B
    const s2 = ""; // 0B
    const s3 = "0123456789ABCDEF"; // 16B
    const s4 = "xy"; // 2B -> total = 21B, max_frame = 8 -> frames of 8B, 8B, 5B(END_STREAM)
    const slices = [_][]const u8{ s1, s2, s3, s4 };

    fw.lock();
    try fw.writeDataVecLocked(7, &slices, true, 8);
    try fw.w.flush();
    fw.unlock();

    var pos: usize = 0;
    var assembled: std.ArrayList(u8) = .empty;
    defer assembled.deinit(testing.allocator);
    var frame_lengths: [3]u32 = @splat(0);
    var fidx: usize = 0;
    while (pos < sink.bytes.items.len) : (fidx += 1) {
        const fh = proto.parseHeader(sink.bytes.items[pos..][0..9]);
        pos += 9;
        try testing.expectEqual(proto.FrameType.data, fh.ftype);
        try testing.expectEqual(@as(u31, 7), fh.sid);
        frame_lengths[fidx] = fh.length;
        const is_last = (fidx == 2);
        try testing.expectEqual(is_last, (fh.flags & proto.flag_end_stream) != 0);
        try assembled.appendSlice(testing.allocator, sink.bytes.items[pos .. pos + fh.length]);
        pos += fh.length;
    }
    try testing.expectEqual(@as(usize, 3), fidx);
    try testing.expectEqual([3]u32{ 8, 8, 5 }, frame_lengths);
    try testing.expectEqualStrings("abc0123456789ABCDEFxy", assembled.items);
}
