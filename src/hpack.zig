//! HPACK (RFC 7541) for HTTP/2, split by direction.
//!
//! Builds on the low-level codec in `hpack_codec.zig` (static table, Huffman
//! codec, integer/string coders) but supplies its own `Decoder`/`Encoder`
//! rather than a shared combined context: RFC 7541 §3.2 requires separate
//! encoder and decoder tables, and sharing one corrupts indices under real
//! multiplexing.
//!
//! Split by direction, which also makes the server side lock-free:
//!   * `Decoder` — owns the *request* dynamic table. Only the connection reader
//!     thread decodes (HEADERS must be processed in on-wire order), so it needs
//!     no lock. Implements every representation incl. incremental indexing.
//!   * `Encoder` — stateless. Emits responses as static-table references +
//!     literals *without* dynamic indexing, so it holds no per-connection state
//!     and any worker thread can call it concurrently. Fully RFC-compliant.

const std = @import("std");
const hp = @import("hpack_codec.zig");

pub const Header = struct { name: []const u8, value: []const u8 };

/// Number of entries in the RFC 7541 static table (61). The combined HPACK
/// index space is `1..=static_len` static, then `static_len+1..` dynamic
/// (newest first).
const static_len = hp.StaticTable.entries.len;

pub const Error = error{
    InvalidIndex,
    InvalidZeroIndex,
    TableSizeExceeded,
    Truncated,
    /// From the codec's integer coder; unreachable in practice (our buffers are
    /// sized for 64-bit values) but part of its return type, so we admit it.
    BufferTooSmall,
} || std.mem.Allocator.Error;

/// Decodes a request header block. Holds the connection's request-side dynamic
/// table; single-threaded use (connection reader) only.
pub const Decoder = struct {
    dyn: hp.DynamicTable,
    /// Upper bound the peer may set via a dynamic-table-size-update; equals the
    /// `SETTINGS_HEADER_TABLE_SIZE` we advertised.
    max_table_size: usize,

    pub fn init(gpa: std.mem.Allocator, max_table_size: usize) Decoder {
        return .{
            .dyn = hp.DynamicTable.initWithSize(gpa, max_table_size),
            .max_table_size = max_table_size,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.dyn.deinit();
    }

    /// Resolves a combined HPACK index (1-based) to a name/value pair, slices
    /// into either static program memory or the dynamic table's storage.
    fn lookup(self: *const Decoder, idx: usize) Error!hp.StaticTable.Entry {
        if (idx == 0) return Error.InvalidZeroIndex;
        if (idx <= static_len) return hp.StaticTable.get(idx) orelse Error.InvalidIndex;
        return self.dyn.get(idx - static_len - 1) orelse Error.InvalidIndex;
    }

    /// Decodes `block` into headers allocated on `arena`. All returned names and
    /// values are duped onto `arena` so they stay valid after the dynamic table
    /// evicts entries on a later block (safe to hand to a worker thread).
    pub fn decode(self: *Decoder, arena: std.mem.Allocator, block: []const u8) Error![]Header {
        var out: std.ArrayList(Header) = .empty;
        var i: usize = 0;
        while (i < block.len) {
            const b = block[i];
            if (b & 0x80 != 0) {
                // 6.1 Indexed Header Field (7-bit prefix).
                const n = try decInt(block[i..], 7);
                i += n.len;
                const e = try self.lookup(@intCast(n.value));
                try out.append(arena, .{ .name = try arena.dupe(u8, e.name), .value = try arena.dupe(u8, e.value) });
            } else if (b & 0xC0 == 0x40) {
                // 6.2.1 Literal with Incremental Indexing (6-bit prefix).
                const h = try self.literal(arena, block[i..], 6);
                i += h.consumed;
                try self.dyn.add(h.name, h.value);
                try out.append(arena, .{ .name = h.name, .value = h.value });
            } else if (b & 0xE0 == 0x20) {
                // 6.3 Dynamic Table Size Update (5-bit prefix).
                const n = try decInt(block[i..], 5);
                i += n.len;
                if (n.value > self.max_table_size) return Error.TableSizeExceeded;
                self.dyn.setMaxSize(@intCast(n.value));
            } else {
                // 6.2.2 Literal without Indexing / 6.2.3 Never Indexed (4-bit prefix).
                // The never-indexed flag (0x10) only matters for re-encoding, which
                // a server doesn't do for inbound headers; either way: not indexed.
                const h = try self.literal(arena, block[i..], 4);
                i += h.consumed;
                try out.append(arena, .{ .name = h.name, .value = h.value });
            }
        }
        return out.toOwnedSlice(arena);
    }

    const Literal = struct { name: []const u8, value: []const u8, consumed: usize };

    /// Decodes a literal representation whose first byte has an `prefix_bits`-wide
    /// name index (0 ⇒ literal name follows). Name/value land on `arena`.
    fn literal(self: *const Decoder, arena: std.mem.Allocator, data: []const u8, prefix_bits: u4) Error!Literal {
        const n = try decInt(data, prefix_bits);
        var i = n.len;
        var name: []const u8 = undefined;
        if (n.value != 0) {
            const e = try self.lookup(@intCast(n.value));
            name = try arena.dupe(u8, e.name);
        } else {
            const s = decStr(data[i..], arena) catch return Error.Truncated;
            name = s.value;
            i += s.len;
        }
        const v = decStr(data[i..], arena) catch return Error.Truncated;
        i += v.len;
        return .{ .name = name, .value = v.value, .consumed = i };
    }
};

/// Stateless response encoder: static-table indexed where possible, otherwise
/// literal-without-indexing (no dynamic-table mutation). Names are lowercased
/// (h2 requires it) and connection-specific headers are dropped.
pub const Encoder = struct {
    /// Appends a complete response header block (`:status` first, then `headers`)
    /// to `out`. `headers` names may be any case; names/values are Huffman-encoded
    /// via `emitLiteral`'s shorter-of-two choice (RFC 7541 §5.2), raw otherwise.
    pub fn encodeResponse(
        arena: std.mem.Allocator,
        out: *std.ArrayList(u8),
        status: u16,
        headers: []const Header,
    ) Error!void {
        // :status — use a static full-entry index when one exists, else literal.
        var sbuf: [3]u8 = undefined;
        const status_str = std.fmt.bufPrint(&sbuf, "{d}", .{status}) catch unreachable;
        if (hp.StaticTable.findNameValue(":status", status_str)) |idx| {
            try emitIndexed(arena, out, idx);
        } else {
            // name index 8 == ":status" (first :status entry in the static table).
            try emitLiteral(arena, out, 8, ":status", status_str);
        }

        for (headers) |h| {
            const lname = try lower(arena, h.name);
            if (isConnectionSpecific(lname)) continue;
            const nidx = hp.StaticTable.findName(lname) orelse 0;
            try emitLiteral(arena, out, nidx, lname, h.value);
        }
    }

    /// Appends a complete **request** header block: the pseudo-headers
    /// `:method`/`:scheme`/`:path`/`:authority` (in order) followed by
    /// `headers`. Used by the HTTP/2 client (e.g. a gRPC client). Names are
    /// lowercased; names/values are Huffman-encoded via `emitLiteral`'s
    /// shorter-of-two choice (RFC 7541 §5.2), raw otherwise.
    pub fn encodeRequest(
        arena: std.mem.Allocator,
        out: *std.ArrayList(u8),
        method: []const u8,
        scheme: []const u8,
        path: []const u8,
        authority: []const u8,
        headers: []const Header,
    ) Error!void {
        try emitPseudo(arena, out, ":method", method);
        try emitPseudo(arena, out, ":scheme", scheme);
        try emitPseudo(arena, out, ":path", path);
        if (authority.len > 0) try emitPseudo(arena, out, ":authority", authority);
        for (headers) |h| {
            const lname = try lower(arena, h.name);
            if (isConnectionSpecific(lname)) continue;
            const nidx = hp.StaticTable.findName(lname) orelse 0;
            try emitLiteral(arena, out, nidx, lname, h.value);
        }
    }

    /// Emits one pseudo-header: an indexed static entry when name+value match
    /// (e.g. `:method GET`), else a literal keyed on the pseudo name's index.
    fn emitPseudo(arena: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) Error!void {
        if (hp.StaticTable.findNameValue(name, value)) |idx| {
            try emitIndexed(arena, out, idx);
        } else {
            const nidx = hp.StaticTable.findName(name) orelse 0;
            try emitLiteral(arena, out, nidx, name, value);
        }
    }

    /// Appends a header-only block (no `:status`) — used for HTTP/2 trailers,
    /// e.g. gRPC's `grpc-status` / `grpc-message`. Names are lowercased; unlike
    /// `encodeResponse`, connection-specific filtering is not applied (trailers
    /// carry only application fields).
    pub fn encodeTrailers(
        arena: std.mem.Allocator,
        out: *std.ArrayList(u8),
        headers: []const Header,
    ) Error!void {
        for (headers) |h| {
            const lname = try lower(arena, h.name);
            const nidx = hp.StaticTable.findName(lname) orelse 0;
            try emitLiteral(arena, out, nidx, lname, h.value);
        }
    }

    fn emitIndexed(arena: std.mem.Allocator, out: *std.ArrayList(u8), idx: usize) Error!void {
        var buf: [10]u8 = undefined;
        const n = hp.encodeInteger(idx, 7, &buf) catch unreachable;
        buf[0] |= 0x80; // Indexed Header Field flag.
        try out.appendSlice(arena, buf[0..n]);
    }

    /// Literal without Indexing (0x00 pattern). `name_idx == 0` ⇒ literal name.
    fn emitLiteral(
        arena: std.mem.Allocator,
        out: *std.ArrayList(u8),
        name_idx: usize,
        name: []const u8,
        value: []const u8,
    ) Error!void {
        var buf: [10]u8 = undefined;
        const n = hp.encodeInteger(name_idx, 4, &buf) catch unreachable;
        // High nibble already 0x0 ⇒ "literal without indexing"; nothing to OR in.
        try out.appendSlice(arena, buf[0..n]);
        // Shorter-of-two: Huffman-encode only when it is strictly smaller than
        // the raw octets (RFC 7541 §5.2); never larger than raw.
        if (name_idx == 0) try hp.encodeString(name, hp.huffmanLen(name) < name.len, arena, out);
        try hp.encodeString(value, hp.huffmanLen(value) < value.len, arena, out);
    }
};

fn lower(arena: std.mem.Allocator, s: []const u8) Error![]const u8 {
    const out = try arena.alloc(u8, s.len);
    for (s, 0..) |ch, i| out[i] = std.ascii.toLower(ch);
    return out;
}

/// Headers forbidden on HTTP/2 (RFC 7540 §8.1.2.2).
fn isConnectionSpecific(lname: []const u8) bool {
    const banned = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (banned) |b| if (std.mem.eql(u8, lname, b)) return true;
    return false;
}

// Thin wrappers so the rest of the file reads against local names. They rebuild
// the result into our own named structs (the codec returns anonymous struct
// types that don't coerce across a `catch`).
const IntResult = struct { value: u64, len: usize };
const StrResult = struct { value: []u8, len: usize };

inline fn decInt(data: []const u8, prefix_bits: u4) Error!IntResult {
    const r = hp.decodeInteger(data, prefix_bits) catch return Error.Truncated;
    return .{ .value = r.value, .len = r.len };
}
inline fn decStr(data: []const u8, arena: std.mem.Allocator) !StrResult {
    const r = try hp.decodeString(data, arena);
    return .{ .value = r.value, .len = r.len };
}

// --- tests ------------------------------------------------------------------

const testing = std.testing;

fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.mem.eql(u8, h.name, name)) return h.value;
    return null;
}

test "decode RFC 7541 C.3.1 first request (no Huffman)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    // :method GET, :scheme http, :path /, :authority www.example.com
    const block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    const hs = try dec.decode(arena, &block);
    try testing.expectEqualStrings("GET", findHeader(hs, ":method").?);
    try testing.expectEqualStrings("http", findHeader(hs, ":scheme").?);
    try testing.expectEqualStrings("/", findHeader(hs, ":path").?);
    try testing.expectEqualStrings("www.example.com", findHeader(hs, ":authority").?);
    // C.2.1-style incremental indexing added :authority to the dynamic table.
    try testing.expectEqual(@as(usize, 1), dec.dyn.len());
}

test "decode RFC 7541 C.4.1 first request (Huffman :authority)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    const block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2,
        0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    };
    const hs = try dec.decode(arena, &block);
    try testing.expectEqualStrings("GET", findHeader(hs, ":method").?);
    try testing.expectEqualStrings("www.example.com", findHeader(hs, ":authority").?);
}

test "decode literal with incremental indexing populates dynamic table (C.2.1)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    // 0x40 (literal+index, new name) "custom-key": "custom-header"
    const block = [_]u8{
        0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y',
        0x0d, 'c',  'u', 's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd',
        'e',  'r',
    };
    const hs = try dec.decode(arena, &block);
    try testing.expectEqualStrings("custom-header", findHeader(hs, "custom-key").?);

    // Index 62 now resolves to the freshly added entry.
    const e = try dec.lookup(static_len + 1);
    try testing.expectEqualStrings("custom-key", e.name);
    try testing.expectEqualStrings("custom-header", e.value);
}

test "encode/decode response round trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "text/plain" }, // mixed case -> lowercased
        .{ .name = "x-cache", .value = "HIT" },
        .{ .name = "transfer-encoding", .value = "chunked" }, // must be dropped
    };
    try Encoder.encodeResponse(arena, &out, 200, &headers);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);

    try testing.expectEqualStrings("200", findHeader(hs, ":status").?);
    try testing.expectEqualStrings("text/plain", findHeader(hs, "content-type").?);
    try testing.expectEqualStrings("HIT", findHeader(hs, "x-cache").?);
    try testing.expectEqual(@as(?[]const u8, null), findHeader(hs, "transfer-encoding"));
}

test "encodeTrailers emits header-only block (grpc-status)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    const trailers = [_]Header{
        .{ .name = "grpc-status", .value = "0" },
        .{ .name = "Grpc-Message", .value = "" }, // mixed case -> lowercased
    };
    try Encoder.encodeTrailers(arena, &out, &trailers);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqualStrings("0", findHeader(hs, "grpc-status").?);
    try testing.expectEqualStrings("", findHeader(hs, "grpc-message").?);
    try testing.expectEqual(@as(?[]const u8, null), findHeader(hs, ":status"));
}

test "encodeRequest emits pseudo-headers then fields (gRPC call)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    const headers = [_]Header{
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };
    try Encoder.encodeRequest(arena, &out, "POST", "https", "/example.greet.Greeter/SayHello", "api.example.com", &headers);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqualStrings("POST", findHeader(hs, ":method").?);
    try testing.expectEqualStrings("https", findHeader(hs, ":scheme").?);
    try testing.expectEqualStrings("/example.greet.Greeter/SayHello", findHeader(hs, ":path").?);
    try testing.expectEqualStrings("api.example.com", findHeader(hs, ":authority").?);
    try testing.expectEqualStrings("application/grpc", findHeader(hs, "content-type").?);
    try testing.expectEqualStrings("trailers", findHeader(hs, "te").?);
}

test "encode non-static status uses literal" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    try Encoder.encodeResponse(arena, &out, 418, &.{});

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqualStrings("418", findHeader(hs, ":status").?);
}

test "dynamic table size update beyond max errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    // 0x3f ... = dynamic table size update (5-bit prefix). Encodes 31 + (127 +
    // 127<<7 + 7<<14) = 131102, well above the 4096 max.
    const block = [_]u8{ 0x3f, 0xff, 0xff, 0x07 };
    try testing.expectError(Error.TableSizeExceeded, dec.decode(arena_state.allocator(), &block));
}

test "hpack integer decode rejects overflow instead of panicking" {
    // A prefix byte at max plus continuation bytes that push the accumulator
    // past 2^64. Before the fix this panicked (integer overflow) in safe
    // builds; now it must return a clean error so a peer can't crash us.
    const data = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
    try testing.expectError(error.IntegerOverflow, hp.decodeInteger(&data, 8));
}

test "Decoder.decode surfaces an overflowing indexed integer as an error" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    // 0x80|... = Indexed Header Field (7-bit prefix) with an overflowing index.
    // The whole server HEADERS path funnels through here; it must not crash.
    const block = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
    try testing.expectError(Error.Truncated, dec.decode(arena_state.allocator(), &block));
}

test "Huffman round trip over short and long codes" {
    // Mixes ≤8-bit codes (ASCII) with long codes (control bytes 0x01/0x02/0x09
    // are 23/28/24 bits) to exercise both the fast table and the slow scan.
    const input = [_]u8{ 'h', 'e', 'l', 'l', 'o', 0x01, ' ', 0x09, 'w', 'o', 'r', 'l', 'd', 0x02, '!' };
    const enc = try hp.HuffmanCodec.encode(&input, testing.allocator);
    defer testing.allocator.free(enc);
    const dec = try hp.HuffmanCodec.decode(enc, testing.allocator);
    defer testing.allocator.free(dec);
    try testing.expectEqualSlices(u8, &input, dec);
}

test "huffmanLen computes the Huffman-encoded byte length" {
    try testing.expectEqual(@as(usize, 0), hp.huffmanLen(""));
    // 'a' is a 5-bit code: 4*5 = 20 bits → 3 bytes.
    try testing.expectEqual(@as(usize, 3), hp.huffmanLen("aaaa"));
    // 0x00 is a 13-bit code: → 2 bytes.
    try testing.expectEqual(@as(usize, 2), hp.huffmanLen("\x00"));
}

test "encode uses Huffman for a value when it is shorter" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    const headers = [_]Header{.{ .name = "x-test", .value = "aaaaaaaaaaaaaaaa" }};
    try Encoder.encodeResponse(arena, &out, 200, &headers);

    // The value's full HPACK string representation, Huffman-encoded (H-bit set).
    var exp: std.ArrayList(u8) = .empty;
    try hp.encodeString("aaaaaaaaaaaaaaaa", true, arena, &exp);
    try testing.expect(std.mem.indexOf(u8, out.items, exp.items) != null);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaa", findHeader(hs, "x-test").?);
}

test "encode keeps a value raw when Huffman would not be shorter" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    // 0x00 Huffman-encodes to 2 bytes vs 1 raw → shorter-of-two keeps it raw.
    const headers = [_]Header{.{ .name = "x-test", .value = "\x00" }};
    try Encoder.encodeResponse(arena, &out, 200, &headers);

    var exp_raw: std.ArrayList(u8) = .empty;
    try hp.encodeString("\x00", false, arena, &exp_raw);
    try testing.expect(std.mem.indexOf(u8, out.items, exp_raw.items) != null);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqualStrings("\x00", findHeader(hs, "x-test").?);
}

test "encode uses Huffman for a literal header name when it is shorter" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    // Name not in the static table → literal-name path (name_idx == 0).
    // Value is a single char that stays raw, isolating the name.
    const headers = [_]Header{.{ .name = "x-custom-long-header-name", .value = "1" }};
    try Encoder.encodeResponse(arena, &out, 200, &headers);

    var exp_name: std.ArrayList(u8) = .empty;
    try hp.encodeString("x-custom-long-header-name", true, arena, &exp_name);
    try testing.expect(std.mem.indexOf(u8, out.items, exp_name.items) != null);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqualStrings("1", findHeader(hs, "x-custom-long-header-name").?);
}
