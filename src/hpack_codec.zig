//! HPACK low-level primitives (RFC 7541), vendored and dependency-free.
//!
//! This is the self-contained subset of the codec that `hpack.zig` builds its
//! split-direction `Decoder`/`Encoder` on top of:
//!   * `StaticTable`  — the 61-entry RFC 7541 Appendix A table + lookups.
//!   * `DynamicTable` — FIFO-evicted dynamic table (size = name + value + 32).
//!   * `encodeInteger`/`decodeInteger` — prefix-bit integer coding (§5.1).
//!   * `encodeString`/`decodeString`   — length-prefixed strings, with the
//!     Huffman flag honored automatically.
//!   * `HuffmanCodec` — RFC 7541 Appendix B codes/lengths + encode/decode.
//!
//! The combined-table `HpackContext` / `encodeHeaders` / `decodeHeaders` from
//! the upstream source are deliberately NOT vendored: they share one dynamic
//! table across both directions, which corrupts indices under real
//! multiplexing (RFC 7541 §3.2 requires separate encoder/decoder tables).
//! `hpack.zig` owns that split instead.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// HPACK static table entries (RFC 7541 Appendix A). Index 1-61 are
/// pre-defined header name/value pairs.
pub const StaticTable = struct {
    pub const Entry = struct { name: []const u8, value: []const u8 };

    pub const entries = [_]Entry{
        .{ .name = ":authority", .value = "" }, // 1
        .{ .name = ":method", .value = "GET" }, // 2
        .{ .name = ":method", .value = "POST" }, // 3
        .{ .name = ":path", .value = "/" }, // 4
        .{ .name = ":path", .value = "/index.html" }, // 5
        .{ .name = ":scheme", .value = "http" }, // 6
        .{ .name = ":scheme", .value = "https" }, // 7
        .{ .name = ":status", .value = "200" }, // 8
        .{ .name = ":status", .value = "204" }, // 9
        .{ .name = ":status", .value = "206" }, // 10
        .{ .name = ":status", .value = "304" }, // 11
        .{ .name = ":status", .value = "400" }, // 12
        .{ .name = ":status", .value = "404" }, // 13
        .{ .name = ":status", .value = "500" }, // 14
        .{ .name = "accept-charset", .value = "" }, // 15
        .{ .name = "accept-encoding", .value = "gzip, deflate" }, // 16
        .{ .name = "accept-language", .value = "" }, // 17
        .{ .name = "accept-ranges", .value = "" }, // 18
        .{ .name = "accept", .value = "" }, // 19
        .{ .name = "access-control-allow-origin", .value = "" }, // 20
        .{ .name = "age", .value = "" }, // 21
        .{ .name = "allow", .value = "" }, // 22
        .{ .name = "authorization", .value = "" }, // 23
        .{ .name = "cache-control", .value = "" }, // 24
        .{ .name = "content-disposition", .value = "" }, // 25
        .{ .name = "content-encoding", .value = "" }, // 26
        .{ .name = "content-language", .value = "" }, // 27
        .{ .name = "content-length", .value = "" }, // 28
        .{ .name = "content-location", .value = "" }, // 29
        .{ .name = "content-range", .value = "" }, // 30
        .{ .name = "content-type", .value = "" }, // 31
        .{ .name = "cookie", .value = "" }, // 32
        .{ .name = "date", .value = "" }, // 33
        .{ .name = "etag", .value = "" }, // 34
        .{ .name = "expect", .value = "" }, // 35
        .{ .name = "expires", .value = "" }, // 36
        .{ .name = "from", .value = "" }, // 37
        .{ .name = "host", .value = "" }, // 38
        .{ .name = "if-match", .value = "" }, // 39
        .{ .name = "if-modified-since", .value = "" }, // 40
        .{ .name = "if-none-match", .value = "" }, // 41
        .{ .name = "if-range", .value = "" }, // 42
        .{ .name = "if-unmodified-since", .value = "" }, // 43
        .{ .name = "last-modified", .value = "" }, // 44
        .{ .name = "link", .value = "" }, // 45
        .{ .name = "location", .value = "" }, // 46
        .{ .name = "max-forwards", .value = "" }, // 47
        .{ .name = "proxy-authenticate", .value = "" }, // 48
        .{ .name = "proxy-authorization", .value = "" }, // 49
        .{ .name = "range", .value = "" }, // 50
        .{ .name = "referer", .value = "" }, // 51
        .{ .name = "refresh", .value = "" }, // 52
        .{ .name = "retry-after", .value = "" }, // 53
        .{ .name = "server", .value = "" }, // 54
        .{ .name = "set-cookie", .value = "" }, // 55
        .{ .name = "strict-transport-security", .value = "" }, // 56
        .{ .name = "transfer-encoding", .value = "" }, // 57
        .{ .name = "user-agent", .value = "" }, // 58
        .{ .name = "vary", .value = "" }, // 59
        .{ .name = "via", .value = "" }, // 60
        .{ .name = "www-authenticate", .value = "" }, // 61
    };

    /// Looks up a header by index (1-based).
    pub fn get(index: usize) ?Entry {
        if (index == 0 or index > entries.len) return null;
        return entries[index - 1];
    }

    /// Finds the index of a header name (returns first match).
    pub fn findName(name: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) {
                return i + 1;
            }
        }
        return null;
    }

    /// Finds the index of a header name+value pair.
    pub fn findNameValue(name: []const u8, value: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name) and mem.eql(u8, entry.value, value)) {
                return i + 1;
            }
        }
        return null;
    }
};

/// Dynamic table entry.
pub const DynamicEntry = struct {
    name: []u8,
    value: []u8,

    pub fn size(self: DynamicEntry) usize {
        // RFC 7541: size = len(name) + len(value) + 32
        return self.name.len + self.value.len + 32;
    }
};

/// HPACK dynamic table with FIFO eviction.
pub const DynamicTable = struct {
    allocator: Allocator,
    entries: std.ArrayList(DynamicEntry) = .empty,
    current_size: usize = 0,
    max_size: usize = 4096, // Default per RFC 7541

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn initWithSize(allocator: Allocator, max_size: usize) Self {
        return .{ .allocator = allocator, .max_size = max_size };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.entries.deinit(self.allocator);
    }

    /// Adds a new entry to the beginning of the dynamic table. Evicts old
    /// entries if necessary to fit within max_size.
    pub fn add(self: *Self, name: []const u8, value: []const u8) !void {
        const entry_size = name.len + value.len + 32;

        // Evict entries until we have room.
        while (self.current_size + entry_size > self.max_size and self.entries.items.len > 0) {
            self.evictOne();
        }

        // If a single entry is larger than max_size, don't add it.
        if (entry_size > self.max_size) return;

        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        // Insert at the beginning (index 0).
        try self.entries.insert(self.allocator, 0, .{
            .name = name_copy,
            .value = value_copy,
        });
        self.current_size += entry_size;
    }

    /// Evicts the oldest entry (last in list).
    fn evictOne(self: *Self) void {
        if (self.entries.items.len == 0) return;
        const entry = self.entries.pop().?;
        self.current_size -= entry.name.len + entry.value.len + 32;
        self.allocator.free(entry.name);
        self.allocator.free(entry.value);
    }

    /// Gets an entry by index (0-based within the dynamic table).
    pub fn get(self: *const Self, index: usize) ?StaticTable.Entry {
        if (index >= self.entries.items.len) return null;
        const entry = self.entries.items[index];
        return .{ .name = entry.name, .value = entry.value };
    }

    /// Updates the maximum size and evicts entries if needed.
    pub fn setMaxSize(self: *Self, new_max: usize) void {
        self.max_size = new_max;
        while (self.current_size > self.max_size and self.entries.items.len > 0) {
            self.evictOne();
        }
    }

    pub fn len(self: *const Self) usize {
        return self.entries.items.len;
    }
};

/// Encodes an integer with the given prefix bits. `prefix_bits`: bits available
/// in the first byte (1-8). Returns the number of bytes written to `out`.
pub fn encodeInteger(value: u64, prefix_bits: u4, out: []u8) !usize {
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;

    if (value < max_prefix) {
        if (out.len < 1) return error.BufferTooSmall;
        out[0] = @intCast(value);
        return 1;
    }

    if (out.len < 1) return error.BufferTooSmall;
    out[0] = @intCast(max_prefix);

    var remaining = value - max_prefix;
    var i: usize = 1;

    while (remaining >= 128) {
        if (i >= out.len) return error.BufferTooSmall;
        out[i] = @intCast((remaining & 0x7F) | 0x80);
        remaining >>= 7;
        i += 1;
    }

    if (i >= out.len) return error.BufferTooSmall;
    out[i] = @intCast(remaining);
    return i + 1;
}

/// Decodes an integer with the given prefix bits. Returns the value and the
/// number of bytes consumed.
pub fn decodeInteger(data: []const u8, prefix_bits: u4) !struct { value: u64, len: usize } {
    if (data.len == 0) return error.UnexpectedEof;

    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    const first_byte_mask: u8 = @intCast(max_prefix);

    var value: u64 = data[0] & first_byte_mask;

    if (value < max_prefix) {
        return .{ .value = value, .len = 1 };
    }

    var i: usize = 1;
    var m: u6 = 0;

    while (i < data.len) {
        const b = data[i];
        // RFC 7541 §5.1: a continuation whose accumulated value does not fit is
        // malformed. Shift and add are BOTH checked — with plain `<<`/`+=` a
        // crafted integer (~10 continuation bytes) overflows u64 and panics in
        // safe builds, i.e. any peer could crash us via a HEADERS block.
        const chunk: u64 = b & 0x7F;
        const shifted = std.math.shlExact(u64, chunk, m) catch return error.IntegerOverflow;
        value = std.math.add(u64, value, shifted) catch return error.IntegerOverflow;
        i += 1;

        if (b & 0x80 == 0) {
            return .{ .value = value, .len = i };
        }

        // Guard before bumping `m`: m is u6, so `m += 7` past 63 would itself
        // overflow. 63 bits of continuation is already more than any real value.
        if (m >= 63) return error.IntegerOverflow;
        m += 7;
    }

    return error.UnexpectedEof;
}

/// Encodes a string (with optional Huffman encoding).
pub fn encodeString(str: []const u8, use_huffman: bool, allocator: Allocator, out: *std.ArrayList(u8)) !void {
    if (use_huffman) {
        const encoded = try HuffmanCodec.encode(str, allocator);
        defer allocator.free(encoded);

        // Length with H bit set.
        var len_buf: [10]u8 = undefined;
        const len_bytes = try encodeInteger(encoded.len, 7, &len_buf);
        len_buf[0] |= 0x80; // Set Huffman flag.
        try out.appendSlice(allocator, len_buf[0..len_bytes]);
        try out.appendSlice(allocator, encoded);
    } else {
        // Length without H bit.
        var len_buf: [10]u8 = undefined;
        const len_bytes = try encodeInteger(str.len, 7, &len_buf);
        try out.appendSlice(allocator, len_buf[0..len_bytes]);
        try out.appendSlice(allocator, str);
    }
}

/// Decodes a string (handles Huffman encoding automatically).
pub fn decodeString(data: []const u8, allocator: Allocator) !struct { value: []u8, len: usize } {
    if (data.len == 0) return error.UnexpectedEof;

    const huffman = (data[0] & 0x80) != 0;
    const len_result = try decodeInteger(data, 7);
    const str_len: usize = @intCast(len_result.value);
    const total_len = len_result.len + str_len;

    if (data.len < total_len) return error.UnexpectedEof;

    const str_data = data[len_result.len..total_len];

    if (huffman) {
        const decoded = try HuffmanCodec.decode(str_data, allocator);
        return .{ .value = decoded, .len = total_len };
    } else {
        const copy = try allocator.dupe(u8, str_data);
        return .{ .value = copy, .len = total_len };
    }
}

/// Huffman codec for HPACK encoding/decoding. Codes and lengths are from
/// RFC 7541 Appendix B.
pub const HuffmanCodec = struct {
    const codes = [256]u32{
        0x1ff8,    0x7fffd8,  0xfffffe2,  0xfffffe3, 0xfffffe4, 0xfffffe5,  0xfffffe6,  0xfffffe7,
        0xfffffe8, 0xffffea,  0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb,  0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef,  0xffffff0, 0xffffff1, 0xffffff2,  0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6,  0xffffff7, 0xffffff8, 0xffffff9,  0xffffffa,  0xffffffb,
        0x14,      0x3f8,     0x3f9,      0xffa,     0x1ff9,    0x15,       0xf8,       0x7fa,
        0x3fa,     0x3fb,     0xf9,       0x7fb,     0xfa,      0x16,       0x17,       0x18,
        0x0,       0x1,       0x2,        0x19,      0x1a,      0x1b,       0x1c,       0x1d,
        0x1e,      0x1f,      0x5c,       0xfb,      0x7ffc,    0x20,       0xffb,      0x3fc,
        0x1ffa,    0x21,      0x5d,       0x5e,      0x5f,      0x60,       0x61,       0x62,
        0x63,      0x64,      0x65,       0x66,      0x67,      0x68,       0x69,       0x6a,
        0x6b,      0x6c,      0x6d,       0x6e,      0x6f,      0x70,       0x71,       0x72,
        0xfc,      0x73,      0xfd,       0x1ffb,    0x7fff0,   0x1ffc,     0x3ffc,     0x22,
        0x7ffd,    0x3,       0x23,       0x4,       0x24,      0x5,        0x25,       0x26,
        0x27,      0x6,       0x74,       0x75,      0x28,      0x29,       0x2a,       0x7,
        0x2b,      0x76,      0x2c,       0x8,       0x9,       0x2d,       0x77,       0x78,
        0x79,      0x7a,      0x7b,       0x7ffe,    0x7fc,     0x3ffd,     0x1ffd,     0xffffffc,
        0xfffe6,   0x3fffd2,  0xfffe7,    0xfffe8,   0x3fffd3,  0x3fffd4,   0x3fffd5,   0x7fffd9,
        0x3fffd6,  0x7fffda,  0x7fffdb,   0x7fffdc,  0x7fffdd,  0x7fffde,   0xffffeb,   0x7fffdf,
        0xffffec,  0xffffed,  0x3fffd7,   0x7fffe0,  0xffffee,  0x7fffe1,   0x7fffe2,   0x7fffe3,
        0x7fffe4,  0x1fffdc,  0x3fffd8,   0x7fffe5,  0x3fffd9,  0x7fffe6,   0x7fffe7,   0xffffef,
        0x3fffda,  0x1fffdd,  0xfffe9,    0x3fffdb,  0x3fffdc,  0x7fffe8,   0x7fffe9,   0x1fffde,
        0x7fffea,  0x3fffdd,  0x3fffde,   0xfffff0,  0x1fffdf,  0x3fffdf,   0x7fffeb,   0x7fffec,
        0x1fffe0,  0x1fffe1,  0x3fffe0,   0x1fffe2,  0x7fffed,  0x3fffe1,   0x7fffee,   0x7fffef,
        0xfffea,   0x3fffe2,  0x3fffe3,   0x3fffe4,  0x7ffff0,  0x3fffe5,   0x3fffe6,   0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb,    0x7fff1,   0x3fffe7,  0x7ffff2,   0x3fffe8,   0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4,  0x7ffffde, 0x7ffffdf, 0x3ffffe5,  0xfffff1,   0x1ffffed,
        0x7fff2,   0x1fffe3,  0x3ffffe6,  0x7ffffe0, 0x7ffffe1, 0x3ffffe7,  0x7ffffe2,  0xfffff2,
        0x1fffe4,  0x1fffe5,  0x3ffffe8,  0x3ffffe9, 0xffffffd, 0x7ffffe3,  0x7ffffe4,  0x7ffffe5,
        0xfffec,   0xfffff3,  0xfffed,    0x1fffe6,  0x3fffe9,  0x1fffe7,   0x1fffe8,   0x7ffff3,
        0x3fffea,  0x3fffeb,  0x1ffffee,  0x1ffffef, 0xfffff4,  0xfffff5,   0x3ffffea,  0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec,  0x3ffffed, 0x7ffffe7, 0x7ffffe8,  0x7ffffe9,  0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec,  0x7ffffed, 0x7ffffee, 0x7ffffef,  0x7fffff0,  0x3ffffee,
    };

    const lengths = [256]u5{
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
        5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10,
        13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
        7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
        15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
        6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    };

    /// Encodes data using Huffman coding.
    pub fn encode(data: []const u8, allocator: Allocator) ![]u8 {
        var result = std.ArrayList(u8).empty;
        errdefer result.deinit(allocator);

        var bit_buffer: u64 = 0;
        var bit_count: u6 = 0;

        for (data) |byte| {
            const code = codes[byte];
            const len = lengths[byte];

            bit_buffer = (bit_buffer << len) | code;
            bit_count += len;

            while (bit_count >= 8) {
                bit_count -= 8;
                try result.append(allocator, @intCast((bit_buffer >> bit_count) & 0xFF));
            }
        }

        // Pad with EOS prefix bits if needed.
        if (bit_count > 0) {
            const pad_bits: u6 = 8 - bit_count;
            bit_buffer = (bit_buffer << pad_bits) | ((@as(u64, 1) << pad_bits) - 1);
            try result.append(allocator, @intCast(bit_buffer & 0xFF));
        }

        return result.toOwnedSlice(allocator);
    }

    /// Decodes a symbol for a given top-8-bit window when the shortest matching
    /// code is ≤8 bits (the common case — most ASCII). `len == 0` marks windows
    /// whose shortest code is longer (rare bytes); those take the slow path.
    const FastDecode = struct { sym: u8, len: u4 };
    const fast_decode_table = blk: {
        @setEvalBranchQuota(300_000);
        var t: [256]FastDecode = undefined;
        for (0..256) |w| {
            var entry: FastDecode = .{ .sym = 0, .len = 0 };
            var L: usize = 5;
            while (L <= 8) : (L += 1) {
                const want: u32 = @intCast(w >> @intCast(8 - L));
                for (codes, 0..) |code, sym| {
                    if (lengths[sym] == L and code == want) {
                        entry = .{ .sym = @intCast(sym), .len = @intCast(L) };
                        break;
                    }
                }
                if (entry.len != 0) break;
            }
            t[w] = entry;
        }
        break :blk t;
    };

    /// Decodes Huffman-encoded data. The common ≤8-bit codes resolve through a
    /// comptime 256-entry table (O(1) per symbol); only the rare long codes
    /// (9..30 bits) fall back to a length-ascending scan. Bounded by the
    /// caller's header-block cap, so the worst case is no worse than before.
    pub fn decode(data: []const u8, allocator: Allocator) ![]u8 {
        var result = std.ArrayList(u8).empty;
        errdefer result.deinit(allocator);

        var bit_buffer: u64 = 0;
        var bit_count: u6 = 0;

        for (data) |byte| {
            bit_buffer = (bit_buffer << 8) | byte;
            bit_count += 8;

            while (bit_count >= 5) {
                // Fast path: a ≤8-bit code is decodable from the top 8 bits.
                if (bit_count >= 8) {
                    const peek: u8 = @intCast((bit_buffer >> (bit_count - 8)) & 0xFF);
                    const e = fast_decode_table[peek];
                    if (e.len != 0) {
                        try result.append(allocator, e.sym);
                        bit_count -= e.len;
                        continue;
                    }
                }
                // Slow path: long codes (9..30 bits), or the final <8-bit window.
                var matched = false;
                var L: u5 = if (bit_count >= 8) 9 else 5;
                while (L <= 30 and L <= bit_count) : (L += 1) {
                    const shift: u6 = @intCast(bit_count - L);
                    const mask: u64 = (@as(u64, 1) << L) - 1;
                    const cand: u64 = (bit_buffer >> shift) & mask;
                    for (codes, 0..) |code, sym| {
                        if (lengths[sym] == L and @as(u64, code) == cand) {
                            try result.append(allocator, @intCast(sym));
                            bit_count -= L;
                            matched = true;
                            break;
                        }
                    }
                    if (matched) break;
                }
                if (!matched) {
                    // With a full longest-code window (30 bits, the max in the
                    // table) available and still no match, the leading bits can
                    // start no valid code — malformed input, or an in-stream EOS
                    // symbol, which RFC 7541 §5.2 forbids. Reject it. This also
                    // bounds bit_count: we only fall through to read another
                    // byte while bit_count < 30, so it never grows past ~37 and
                    // can no longer overflow the u6 on adversarial all-ones runs.
                    if (bit_count >= 30) return error.InvalidHuffmanCode;
                    break;
                }
            }
        }

        // Remaining bits should be EOS padding (all 1s).
        if (bit_count > 7) return error.InvalidHuffmanPadding;
        if (bit_count > 0) {
            const mask = (@as(u64, 1) << bit_count) - 1;
            if ((bit_buffer & mask) != mask) return error.InvalidHuffmanPadding;
        }

        return result.toOwnedSlice(allocator);
    }
};

/// Byte length `str` would occupy Huffman-encoded (RFC 7541 §5.2): the sum of
/// per-symbol code lengths in bits, rounded up to whole bytes (the EOS padding
/// fills the final partial byte). Cheap O(n) scan, no allocation — used to
/// decide whether Huffman is shorter than the raw string before encoding.
pub fn huffmanLen(str: []const u8) usize {
    var bits: usize = 0;
    for (str) |b| bits += HuffmanCodec.lengths[b];
    return (bits + 7) / 8;
}
