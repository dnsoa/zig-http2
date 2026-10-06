//! Shared HTTP/2 wire primitives (RFC 7540): the connection preface, frame
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
    enhance_your_calm = 0xb,
    _,
};

// SETTINGS identifiers.
pub const set_header_table_size: u16 = 0x1;
pub const set_enable_push: u16 = 0x2;
pub const set_max_concurrent_streams: u16 = 0x3;
pub const set_initial_window_size: u16 = 0x4;
pub const set_max_frame_size: u16 = 0x5;

// Common defaults / limits.
pub const our_max_frame_size: u32 = 16384;
pub const our_header_table_size: u32 = 4096;
pub const default_window: i64 = 65535;

pub const ParsedHeader = struct { length: u32, ftype: FrameType, flags: u8, sid: u31 };

pub fn putHeader(buf: *[9]u8, length: usize, ftype: FrameType, flags: u8, sid: u31) void {
    buf[0] = @intCast((length >> 16) & 0xff);
    buf[1] = @intCast((length >> 8) & 0xff);
    buf[2] = @intCast(length & 0xff);
    buf[3] = @intFromEnum(ftype);
    buf[4] = flags;
    std.mem.writeInt(u32, buf[5..9], @as(u32, sid), .big);
}

pub fn parseHeader(b: *const [9]u8) ParsedHeader {
    return .{
        .length = (@as(u32, b[0]) << 16) | (@as(u32, b[1]) << 8) | b[2],
        .ftype = @enumFromInt(b[3]),
        .flags = b[4],
        .sid = @intCast(std.mem.readInt(u32, b[5..9], .big) & 0x7fff_ffff),
    };
}

/// Clamps a configured connection-level receive window to the RFC 7540 §6.9.1
/// range. The floor is the protocol's fixed initial window: a connection may
/// only ever be enlarged from 65535 via WINDOW_UPDATE, never shrunk below it.
/// Shared so client and server agree on what a configured value means.
pub fn clampConnWindow(v: u32) i64 {
    return @intCast(@min(@max(v, 65535), 0x7fff_ffff));
}

/// Clamps a SETTINGS_INITIAL_WINDOW_SIZE to the RFC 7540 §6.5.2 range. Unlike
/// the connection window this has no floor — 0 is legal and simply stalls the
/// peer until a WINDOW_UPDATE arrives.
pub fn clampInitialWindow(v: u32) i64 {
    return @intCast(@min(v, 0x7fff_ffff));
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
