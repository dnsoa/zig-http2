//! Shared HTTP/2 wire primitives (RFC 9113): the connection preface, frame
//! types/flags, error codes, SETTINGS identifiers, and 9-byte frame-header
//! encode/decode. Both the server (`server.zig`) and the client (`client.zig`)
//! build on these, so the framing stays defined once.

const std = @import("std");

pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

pub const flag_ack: u8 = 0x1; // SETTINGS / PING
pub const flag_end_stream: u8 = 0x1; // DATA / HEADERS
pub const flag_end_headers: u8 = 0x4; // HEADERS / CONTINUATION
pub const flag_padded: u8 = 0x8; // DATA / HEADERS
pub const flag_priority: u8 = 0x20; // HEADERS

pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    enhance_your_calm = 0xb,
    _,
};

// SETTINGS identifiers.
pub const set_header_table_size: u16 = 0x1;
pub const set_enable_push: u16 = 0x2;
pub const set_max_concurrent_streams: u16 = 0x3;
pub const set_initial_window_size: u16 = 0x4;
pub const set_max_frame_size: u16 = 0x5;
pub const set_max_header_list_size: u16 = 0x6;

// Common defaults / limits.
pub const our_max_frame_size: u32 = 16384;
pub const our_header_table_size: u32 = 4096;
pub const default_window: i64 = 65535;

/// Clamps a configured connection-level receive window to the RFC 9113 range
/// `[65535, 2^31-1]` (a connection window starts at 65535 and can only grow).
pub fn clampConnWindow(v: u32) i64 {
    return @intCast(@min(@max(v, 65535), 0x7fff_ffff));
}

/// Clamps a configured `SETTINGS_INITIAL_WINDOW_SIZE` to the RFC 9113 §6.5.2
/// range `[0, 2^31-1]` so misconfiguration never emits an illegal setting.
pub fn clampInitialWindow(v: u32) u32 {
    return @min(v, 0x7fff_ffff);
}

/// Clamps a configured `SETTINGS_MAX_FRAME_SIZE` to the RFC 9113 §6.5.2 range
/// `[16384, 16777215]` (`[2^14, 2^24-1]`).
pub fn clampMaxFrameSize(v: u32) u32 {
    return @min(@max(v, our_max_frame_size), 16777215);
}

const TimedOp = union(enum) { work: anyerror!void, timer: void };

fn timerThunk(io: std.Io, ms: u64) void {
    std.Io.sleep(io, .{ .nanoseconds = @as(i96, ms) * std.time.ns_per_ms }, .awake) catch {};
}

/// Runs blocking `f(args...)` (must return `anyerror!void`) raced against a `ms`
/// deadline; returns `error.Timeout` when the deadline wins. The loser is
/// canceled. `ms == 0` disables the deadline and invokes `f` inline.
pub fn runTimed(io: std.Io, ms: u64, f: anytype, args: anytype) anyerror!void {
    if (ms == 0) return @call(.auto, f, args);
    var buf: [2]TimedOp = undefined;
    var sel = std.Io.Select(TimedOp).init(io, &buf);
    // Spawn the timer first so if only one concurrency slot is available and
    // `.work` fails to spawn, `.work` is never cancelled mid-flight after
    // consuming or emitting partial transport bytes.
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

/// Bounded circular byte buffer for inbound HTTP/2 stream DATA (`O(window_size)`
/// across sustained streaming reads even when never drained completely to zero).
pub const RxRing = struct {
    buf: []u8 = &.{},
    head: usize = 0,
    len: usize = 0,

    pub fn deinit(self: *RxRing, gpa: std.mem.Allocator) void {
        if (self.buf.len > 0) gpa.free(self.buf);
        self.* = .{};
    }

    pub fn appendSlice(self: *RxRing, gpa: std.mem.Allocator, data: []const u8) !void {
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

    pub fn read(self: *RxRing, dst: []u8) usize {
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

pub const ParsedHeader = struct { length: u32, ftype: FrameType, flags: u8, sid: u31 };

pub fn putHeader(buf: *[9]u8, length: usize, ftype: FrameType, flags: u8, sid: u31) void {
    buf[0] = @intCast((length >> 16) & 0xff);
    buf[1] = @intCast((length >> 8) & 0xff);
    buf[2] = @intCast(length & 0xff);
    buf[3] = @backingInt(ftype);
    buf[4] = flags;
    std.mem.writeInt(u32, buf[5..9], @as(u32, sid), .big);
}

pub fn parseHeader(b: *const [9]u8) ParsedHeader {
    return .{
        .length = (@as(u32, b[0]) << 16) | (@as(u32, b[1]) << 8) | b[2],
        .ftype = @fromBackingInt(@intCast(b[3])),
        .flags = b[4],
        .sid = @intCast(std.mem.readInt(u32, b[5..9], .big) & 0x7fff_ffff),
    };
}

pub fn putSetting(buf: *[6]u8, id: u16, value: u32) void {
    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u32, buf[2..6], value, .big);
}

/// Returns a connection-error code when `fh`/`payload` violate framing rules
/// (RFC 7540 §4/§6), or null when the frame is structurally acceptable. Shared
/// by the server read loop and the client reader thread — both must reject the
/// same mistakes, so the rules live once here.
pub fn validateInboundFrame(fh: ParsedHeader, payload: []const u8) ?ErrorCode {
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
        .headers, .data, .continuation => {
            if (fh.sid == 0) return .protocol_error;
        },
        .rst_stream => {
            if (fh.sid == 0) return .protocol_error;
            if (payload.len != 4) return .frame_size_error; // RFC 7540 §6.4
        },
        .priority => {
            if (fh.sid == 0) return .protocol_error;
            if (payload.len != 5) return .frame_size_error; // RFC 7540 §6.3
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

/// RFC 9110 §5.6.2 `tchar`: allowed characters in an HTTP token / field name.
pub fn isTokenChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or switch (ch) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// RFC 9113 §8.2.1 & RFC 9110 §5.1 / §5.6.2: regular HTTP/2 field names MUST
/// be non-empty lowercase `tchar` sequences (rejects delimiters, CTLs,
/// uppercase ASCII, and `:`).
pub fn isValidFieldName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| {
        if (std.ascii.isUpper(ch) or !isTokenChar(ch)) return false;
    }
    return true;
}

/// RFC 9113 §8.2.1 & RFC 9110 §5.5: field values MUST NOT start or end with
/// SP (0x20) or HTAB (0x09), and MUST NOT contain NUL, CR, LF, or other CTLs
/// (0x00-0x08, 0x0a-0x1f, 0x7f).
pub fn isValidFieldValue(value: []const u8) bool {
    if (value.len == 0) return true;
    if (value[0] == ' ' or value[0] == '\t') return false;
    if (value[value.len - 1] == ' ' or value[value.len - 1] == '\t') return false;
    for (value) |ch| {
        if ((ch < 0x20 and ch != '\t') or ch == 0x7f) return false;
    }
    return true;
}

/// RFC 9113 §8.2.2: connection-specific header fields forbidden in HTTP/2.
pub fn isConnectionSpecificHeader(name: []const u8) bool {
    const banned = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (banned) |b| {
        if (std.ascii.eqlIgnoreCase(name, b)) return true;
    }
    return false;
}

/// RFC 9110 §5.6.2 token (`tchar+`): used to validate `:method`.
pub fn isValidToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |ch| {
        if (!isTokenChar(ch)) return false;
    }
    return true;
}

/// RFC 3986 §3.1 scheme (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`).
pub fn isValidScheme(s: []const u8) bool {
    if (s.len == 0 or !std.ascii.isAlphabetic(s[0])) return false;
    for (s[1..]) |ch| {
        const ok = std.ascii.isAlphanumeric(ch) or ch == '+' or ch == '-' or ch == '.';
        if (!ok) return false;
    }
    return true;
}

/// RFC 9110 §8.6 Content-Length (`1*DIGIT`; rejects empty, signs, and `_`).
pub fn parseContentLength(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    for (s) |ch| {
        if (!std.ascii.isDigit(ch)) return null;
    }
    return std.fmt.parseInt(u64, s, 10) catch null;
}

test "proto field and token validators enforce RFC 9113 / RFC 9110 rules" {
    const testing = std.testing;
    try testing.expect(isValidFieldName("x-custom-1"));
    try testing.expect(isValidFieldName("!#$%&'*+-.^_`|~09az"));
    try testing.expect(!isValidFieldName(""));
    try testing.expect(!isValidFieldName("X-Upper"));
    try testing.expect(!isValidFieldName(":pseudo"));
    try testing.expect(!isValidFieldName("bad name"));
    // RFC 9110 §5.6.2: delimiters are not valid tchar in HTTP field names (#37).
    const bad_delims = [_][]const u8{
        "a,b", "a;b", "a=b", "a/b", "a\"b", "a(b",  "a)b",
        "a{b", "a}b", "a[b", "a]b", "a@b",  "a\\b", "a<b",
        "a>b", "a?b",
    };
    for (bad_delims) |name| {
        try testing.expect(!isValidFieldName(name));
    }

    try testing.expect(isValidFieldValue(""));
    try testing.expect(isValidFieldValue("a\tb c"));
    try testing.expect(!isValidFieldValue(" leading"));
    try testing.expect(!isValidFieldValue("trailing\t"));
    try testing.expect(!isValidFieldValue("ctl\x07val"));
    try testing.expect(!isValidFieldValue("del\x7fval"));

    try testing.expect(isValidToken("GET"));
    try testing.expect(!isValidToken("GET /"));
    try testing.expect(isValidScheme("https"));
    try testing.expect(isValidScheme("coap+tcp"));
    try testing.expect(!isValidScheme("1http"));
    try testing.expect(!isValidScheme("ht_tp"));

    try testing.expectEqual(@as(?u64, 42), parseContentLength("42"));
    try testing.expectEqual(@as(?u64, null), parseContentLength("+42"));
    try testing.expectEqual(@as(?u64, null), parseContentLength("4_2"));

    // Window clamping helpers (#38, #39).
    try testing.expectEqual(@as(i64, 65535), clampConnWindow(0));
    try testing.expectEqual(@as(i64, 65535), clampConnWindow(100));
    try testing.expectEqual(@as(i64, 1 << 20), clampConnWindow(1 << 20));
    try testing.expectEqual(@as(i64, 0x7fff_ffff), clampConnWindow(0xffff_ffff));

    try testing.expectEqual(@as(u32, 0), clampInitialWindow(0));
    try testing.expectEqual(@as(u32, 131072), clampInitialWindow(131072));
    try testing.expectEqual(@as(u32, 0x7fff_ffff), clampInitialWindow(0x8000_0000));
    try testing.expectEqual(@as(u32, 0x7fff_ffff), clampInitialWindow(0xffff_ffff));

    try testing.expectEqual(@as(u32, 16384), clampMaxFrameSize(0));
    try testing.expectEqual(@as(u32, 16384), clampMaxFrameSize(4096));
    try testing.expectEqual(@as(u32, 65536), clampMaxFrameSize(65536));
    try testing.expectEqual(@as(u32, 16777215), clampMaxFrameSize(32 * 1024 * 1024));
}
