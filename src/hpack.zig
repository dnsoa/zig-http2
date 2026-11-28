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
const types = @import("types.zig");
const proto = @import("proto.zig");
const hp = @import("hpack_codec.zig");

pub const Header = types.Header;

/// Returns true when `s` points into the static table's `.rodata` blob and
/// therefore must not be passed to `Allocator.free` (nor re-duped into arenas).
pub inline fn isStaticSlice(s: []const u8) bool {
    return hp.StaticTable.isStaticSlice(s);
}

/// Frees `s` iff it is a non-empty heap slice outside `StaticTable.static_blob`.
pub inline fn freeSlice(alloc: std.mem.Allocator, s: []const u8) void {
    if (s.len > 0 and !hp.StaticTable.isStaticSlice(s)) alloc.free(s);
}

/// Frees a `Header` slice allocated by `Decoder.decode` on a general-purpose
/// allocator, safely skipping borrowed `StaticTable` slices.
pub fn freeHeaders(alloc: std.mem.Allocator, hs: []const Header) void {
    for (hs) |h| {
        freeSlice(alloc, h.name);
        freeSlice(alloc, h.value);
    }
    alloc.free(hs);
}

/// Number of entries in the RFC 7541 static table (61). The combined HPACK
/// index space is `1..=static_len` static, then `static_len+1..` dynamic
/// (newest first).
const static_len = hp.StaticTable.entries.len;

pub const Error = error{
    InvalidIndex,
    InvalidZeroIndex,
    TableSizeExceeded,
    /// A dynamic table size update appeared after a header field representation
    /// (RFC 7541 §4.2 / §6.3: updates may only occur at the start of a block).
    InvalidTableSizeUpdate,
    Truncated,
    /// Decoded header list exceeded `Decoder.max_list_size` — an HPACK
    /// decompression bomb (RFC 7540 §6.5.2 SETTINGS_MAX_HEADER_LIST_SIZE).
    HeaderListTooLarge,
    /// Outbound header name or value violated RFC 9113 / RFC 9110 syntax
    /// (e.g. CRLF, NUL, leading/trailing whitespace, or injected `:pseudo`).
    InvalidHeader,
    /// From the codec's integer coder; unreachable in practice (our buffers are
    /// sized for 64-bit values) but part of its return type, so we admit it.
    BufferTooSmall,
} || std.mem.Allocator.Error;

/// Default cap on the *decoded* header-list size — the RFC 7540 §6.5.2 metric:
/// sum over fields of (name.len + value.len + 32). Bounds HPACK decompression
/// bombs, where a small block of 1-byte indexed references to a large dynamic
/// table entry expands to gigabytes. Sized above any legitimate header set that
/// fits the wire-side block cap, so it never rejects real traffic.
pub const default_max_header_list_size: usize = 512 * 1024;

/// Decodes a request header block. Holds the connection's request-side dynamic
/// table; single-threaded use (connection reader) only.
pub const Decoder = struct {
    dyn: hp.DynamicTable,
    /// Upper bound the peer may set via a dynamic-table-size-update; equals the
    /// `SETTINGS_HEADER_TABLE_SIZE` we advertised.
    max_table_size: usize,
    /// Cap on the decoded header-list size for a single block; 0 disables it.
    /// Defaults to `default_max_header_list_size`; callers may lower it.
    max_list_size: usize = default_max_header_list_size,

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
    fn lookup(self: *const Decoder, idx: u64) Error!hp.StaticTable.Entry {
        if (idx == 0) return Error.InvalidZeroIndex;
        if (idx <= static_len) return hp.StaticTable.get(@intCast(idx)) orelse Error.InvalidIndex;
        const dyn_idx = std.math.cast(usize, idx - static_len - 1) orelse return Error.InvalidIndex;
        return self.dyn.get(dyn_idx) orelse Error.InvalidIndex;
    }

    /// Decodes `block` into headers allocated on `arena`. Static-table names
    /// and values are borrowed directly from `.rodata` with zero `dupe` calls;
    /// dynamic-table and literal strings are duped onto `arena` so they stay
    /// valid after later dynamic evictions (safe to hand to a worker thread).
    pub fn decode(self: *Decoder, arena: std.mem.Allocator, block: []const u8) Error![]Header {
        var out: std.ArrayList(Header) = .empty;
        // On any decode error (e.g. a malformed/hostile block), free everything
        // heap-allocated so a caller passing `gpa` does not leak.
        errdefer {
            for (out.items) |h| {
                freeSlice(arena, h.name);
                freeSlice(arena, h.value);
            }
            out.deinit(arena);
        }
        var list_size: usize = 0;
        var saw_field = false;
        var i: usize = 0;
        while (i < block.len) {
            const b = block[i];
            if (b & 0x80 != 0) {
                // 6.1 Indexed Header Field (7-bit prefix).
                saw_field = true;
                const n = try decInt(block[i..], 7);
                i += n.len;
                const e = try self.lookup(n.value);
                try self.account(&list_size, e.name, e.value);
                if (n.value <= static_len) {
                    try out.append(arena, .{ .name = e.name, .value = e.value });
                } else {
                    try ownEntry(arena, &out, e);
                }
            } else if (b & 0xC0 == 0x40) {
                // 6.2.1 Literal with Incremental Indexing (6-bit prefix).
                saw_field = true;
                const h = try self.literal(arena, block[i..], 6);
                i += h.consumed;
                try own(arena, &out, h.name, h.value);
                try self.account(&list_size, h.name, h.value);
                try self.dyn.add(h.name, h.value);
            } else if (b & 0xE0 == 0x20) {
                // 6.3 Dynamic Table Size Update (5-bit prefix).
                if (saw_field) return Error.InvalidTableSizeUpdate;
                const n = try decInt(block[i..], 5);
                i += n.len;
                if (n.value > self.max_table_size) return Error.TableSizeExceeded;
                self.dyn.setMaxSize(@intCast(n.value));
            } else {
                // 6.2.2 Literal without Indexing / 6.2.3 Never Indexed (4-bit prefix).
                saw_field = true;
                const h = try self.literal(arena, block[i..], 4);
                i += h.consumed;
                try own(arena, &out, h.name, h.value);
                try self.account(&list_size, h.name, h.value);
            }
        }
        return out.toOwnedSlice(arena);
    }

    /// Advances the HPACK dynamic table and enforces all wire/Huffman/`max_list_size`
    /// invariants on `block` **without** allocating a `[]Header` output list or
    /// duping non-indexed strings. Used when refusing streams (`REFUSED_STREAM`,
    /// `STREAM_CLOSED`) under load so excess streams incur zero output heap churn.
    pub fn decodeDiscard(self: *Decoder, block: []const u8) Error!void {
        const gpa = self.dyn.allocator orelse return Error.OutOfMemory;
        var list_size: usize = 0;
        var saw_field = false;
        var i: usize = 0;
        while (i < block.len) {
            const b = block[i];
            if (b & 0x80 != 0) {
                saw_field = true;
                const n = try decInt(block[i..], 7);
                i += n.len;
                const e = try self.lookup(n.value);
                try self.account(&list_size, e.name, e.value);
            } else if (b & 0xC0 == 0x40) {
                saw_field = true;
                const n = try decInt(block[i..], 6);
                i += n.len;

                var name_scratch: [512]u8 = undefined;
                var val_scratch: [512]u8 = undefined;
                var name_owned: ?[]u8 = null;
                defer if (name_owned) |no| gpa.free(no);
                var val_owned: ?[]u8 = null;
                defer if (val_owned) |vo| gpa.free(vo);

                var name_slice: []const u8 = undefined;
                if (n.value != 0) {
                    const e = try self.lookup(n.value);
                    if (n.value <= static_len) {
                        name_slice = e.name;
                    } else if (e.name.len <= name_scratch.len) {
                        // Copy out of `self.dyn.storage` before `self.dyn.add`
                        // can evict or compact the dynamic byte pool.
                        @memcpy(name_scratch[0..e.name.len], e.name);
                        name_slice = name_scratch[0..e.name.len];
                    } else {
                        const duped = try gpa.dupe(u8, e.name);
                        name_owned = duped;
                        name_slice = duped;
                    }
                } else {
                    const ns = try decStrScratch(block[i..], &name_scratch, gpa);
                    name_owned = ns.owned;
                    name_slice = ns.slice;
                    i += ns.consumed;
                }

                const vs = try decStrScratch(block[i..], &val_scratch, gpa);
                val_owned = vs.owned;
                i += vs.consumed;

                try self.account(&list_size, name_slice, vs.slice);
                try self.dyn.add(name_slice, vs.slice);
            } else if (b & 0xE0 == 0x20) {
                if (saw_field) return Error.InvalidTableSizeUpdate;
                const n = try decInt(block[i..], 5);
                i += n.len;
                if (n.value > self.max_table_size) return Error.TableSizeExceeded;
                self.dyn.setMaxSize(@intCast(n.value));
            } else {
                saw_field = true;
                const n = try decInt(block[i..], 4);
                i += n.len;
                var name_len: usize = 0;
                if (n.value != 0) {
                    const e = try self.lookup(n.value);
                    name_len = e.name.len;
                } else {
                    const ns = try decStrLenOnly(block[i..]);
                    name_len = ns.decoded_len;
                    i += ns.consumed;
                }
                const vs = try decStrLenOnly(block[i..]);
                i += vs.consumed;
                list_size = list_size +| name_len +| vs.decoded_len +| 32;
                if (self.max_list_size != 0 and list_size > self.max_list_size) return Error.HeaderListTooLarge;
            }
        }
    }

    /// Adds one field's RFC 7540 §6.5.2 size (name + value + 32) to the running
    /// decoded-list total and rejects the block once it exceeds `max_list_size`
    /// — the guard against HPACK decompression bombs.
    fn account(self: *const Decoder, list_size: *usize, name: []const u8, value: []const u8) Error!void {
        list_size.* = list_size.* +| name.len +| value.len +| 32;
        if (self.max_list_size != 0 and list_size.* > self.max_list_size) return Error.HeaderListTooLarge;
    }

    const Literal = struct { name: []const u8, value: []const u8, consumed: usize };

    fn own(arena: std.mem.Allocator, out: *std.ArrayList(Header), name: []const u8, value: []const u8) Error!void {
        errdefer {
            freeSlice(arena, name);
            freeSlice(arena, value);
        }
        try out.append(arena, .{ .name = name, .value = value });
    }

    /// Dupes a dynamic-table entry onto `arena` and hands ownership to `out`.
    fn ownEntry(arena: std.mem.Allocator, out: *std.ArrayList(Header), e: hp.StaticTable.Entry) Error!void {
        const name = try arena.dupe(u8, e.name);
        errdefer arena.free(name);
        const value = try arena.dupe(u8, e.value);
        errdefer arena.free(value);
        try out.append(arena, .{ .name = name, .value = value });
    }

    /// Decodes a literal representation whose first byte has a `prefix_bits`-wide
    /// name index (0 ⇒ literal name follows). Static-table names are borrowed
    /// from `.rodata`; dynamic names and literal strings land on `arena`.
    fn literal(self: *const Decoder, arena: std.mem.Allocator, data: []const u8, prefix_bits: u4) Error!Literal {
        const n = try decInt(data, prefix_bits);
        var i = n.len;
        var name: []const u8 = undefined;
        if (n.value != 0) {
            const e = try self.lookup(n.value);
            name = if (n.value <= static_len) e.name else try arena.dupe(u8, e.name);
        } else {
            const s = decStr(data[i..], arena) catch return Error.Truncated;
            name = s.value;
            i += s.len;
        }
        errdefer freeSlice(arena, name);
        const v = decStr(data[i..], arena) catch return Error.Truncated;
        i += v.len;
        return .{ .name = name, .value = v.value, .consumed = i };
    }
};

/// Connection-stateful HPACK encoder (RFC 7541) with bounded circular dynamic
/// table, RFC 7541 §4.2 Dynamic Table Size Update tracking, and CDN-oriented
/// selective indexing.
///
/// Must be invoked exclusively under the connection's outbound write lock in
/// exact on-wire `HEADERS` emission order.
pub const EncoderContext = struct {
    dyn: hp.DynamicTable = .{ .max_size = 4096 },
    local_max_size: usize = 4096,
    peer_max_size: usize = 4096,
    pending_min_size: ?usize = null,
    pending_target_size: ?usize = null,

    pub fn initWithMaxSize(local_max: usize) EncoderContext {
        const eff = @min(local_max, 4096);
        return .{
            .dyn = .{ .max_size = eff },
            .local_max_size = local_max,
            .peer_max_size = 4096,
            .pending_min_size = if (eff < 4096) eff else null,
            .pending_target_size = if (eff < 4096) eff else null,
        };
    }

    pub fn deinit(self: *EncoderContext, gpa: std.mem.Allocator) void {
        self.dyn.deinitWithAllocator(gpa);
    }

    /// Configures `local_max_size` before the first outbound header block on a
    /// connection (e.g. from `Config.max_encoder_table_size`).
    pub fn configureLocalMax(self: *EncoderContext, local_max: usize) void {
        self.local_max_size = local_max;
        const eff = @min(local_max, self.peer_max_size);
        if (eff != self.dyn.max_size) {
            self.pending_min_size = if (self.pending_min_size) |m| @min(m, eff) else eff;
            self.pending_target_size = eff;
        }
    }

    /// Records acknowledged peer `SETTINGS_HEADER_TABLE_SIZE` updates (`min_seen`
    /// and `last_seen` within a SETTINGS frame). Preserves intermediate minima
    /// across multiple SETTINGS frames per RFC 7541 §4.2.
    pub fn notePeerHeaderTableSize(self: *EncoderContext, min_seen: u32, last_seen: u32) void {
        self.peer_max_size = last_seen;
        const min_eff = @min(@as(usize, min_seen), self.local_max_size);
        const target_eff = @min(@as(usize, last_seen), self.local_max_size);
        if (self.pending_target_size != null) {
            const prev_min = self.pending_min_size orelse self.dyn.max_size;
            self.pending_min_size = @min(prev_min, min_eff);
            self.pending_target_size = target_eff;
            return;
        }
        if (min_eff < self.dyn.max_size or target_eff != self.dyn.max_size) {
            self.pending_min_size = min_eff;
            self.pending_target_size = target_eff;
        }
    }

    fn flushPendingTableSizeUpdates(self: *EncoderContext, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) Error!void {
        const target = self.pending_target_size orelse return;
        const min_s = self.pending_min_size orelse target;
        var tbuf: [10]u8 = undefined;
        if (min_s < target) {
            try out.appendSlice(gpa, Encoder.encodeTableSizeUpdate(min_s, &tbuf));
            self.dyn.setMaxSize(min_s);
        }
        try out.appendSlice(gpa, Encoder.encodeTableSizeUpdate(target, &tbuf));
        self.dyn.setMaxSize(target);
        self.pending_min_size = null;
        self.pending_target_size = null;
    }

    pub fn encodeResponse(
        self: *EncoderContext,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(u8),
        status: u16,
        headers: []const Header,
        auto_content_length: ?u64,
    ) Error!void {
        // Pre-validate all application headers BEFORE mutating `self.dyn` or
        // flushing pending table-size updates so an invalid header never
        // desynchronizes the connection's HPACK state.
        for (headers) |h| {
            if (!proto.isValidOutboundHeaderName(h.name) or !proto.isValidFieldValue(h.value)) {
                return Error.InvalidHeader;
            }
        }
        try self.flushPendingTableSizeUpdates(gpa, out);

        var sbuf: [5]u8 = undefined;
        const status_str = std.fmt.bufPrint(&sbuf, "{d}", .{status}) catch unreachable;
        try self.emitFieldLower(gpa, out, ":status", status_str);

        var saw_cl = false;
        for (headers) |h| {
            if (isConnectionSpecific(h.name) or std.ascii.eqlIgnoreCase(h.name, "te")) continue;
            if (auto_content_length != null and !saw_cl and std.ascii.eqlIgnoreCase(h.name, "content-length")) {
                saw_cl = true;
            }
            try self.emitField(gpa, out, h.name, h.value);
        }
        if (auto_content_length) |cl| {
            if (!saw_cl) {
                var cl_buf: [20]u8 = undefined;
                const cl_str = std.fmt.bufPrint(&cl_buf, "{d}", .{cl}) catch unreachable;
                try self.emitFieldLower(gpa, out, "content-length", cl_str);
            }
        }
    }

    pub fn encodeRequest(
        self: *EncoderContext,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(u8),
        method: []const u8,
        scheme: []const u8,
        path: []const u8,
        authority: []const u8,
        headers: []const Header,
    ) Error!void {
        return self.encodeRequestEx(gpa, out, method, scheme, path, authority, null, headers);
    }

    pub fn encodeRequestEx(
        self: *EncoderContext,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(u8),
        method: []const u8,
        scheme: []const u8,
        path: []const u8,
        authority: []const u8,
        protocol: ?[]const u8,
        headers: []const Header,
    ) Error!void {
        if (!proto.isValidToken(method) or !proto.isValidFieldValue(scheme) or
            !proto.isValidFieldValue(path) or !proto.isValidFieldValue(authority))
        {
            return Error.InvalidHeader;
        }
        if (protocol) |pr| if (!proto.isValidToken(pr)) return Error.InvalidHeader;
        for (headers) |h| {
            if (!proto.isValidOutboundHeaderName(h.name) or !proto.isValidFieldValue(h.value)) {
                return Error.InvalidHeader;
            }
        }
        try self.flushPendingTableSizeUpdates(gpa, out);

        try self.emitFieldLower(gpa, out, ":method", method);
        if (protocol) |proto_val| try self.emitFieldLower(gpa, out, ":protocol", proto_val);
        try self.emitFieldLower(gpa, out, ":scheme", scheme);
        try self.emitFieldLower(gpa, out, ":path", path);
        if (authority.len > 0) try self.emitFieldLower(gpa, out, ":authority", authority);

        for (headers) |h| {
            if (isConnectionSpecific(h.name)) continue;
            if (std.ascii.eqlIgnoreCase(h.name, "te")) {
                const trimmed = std.mem.trim(u8, h.value, " \t");
                if (!std.ascii.eqlIgnoreCase(trimmed, "trailers")) continue;
                try self.emitFieldLower(gpa, out, "te", "trailers");
                continue;
            }
            try self.emitField(gpa, out, h.name, h.value);
        }
    }

    pub fn encodeTrailers(
        self: *EncoderContext,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(u8),
        headers: []const Header,
    ) Error!void {
        for (headers) |h| {
            if (!proto.isValidOutboundHeaderName(h.name) or !proto.isValidFieldValue(h.value)) {
                return Error.InvalidHeader;
            }
        }
        try self.flushPendingTableSizeUpdates(gpa, out);
        for (headers) |h| {
            try self.emitField(gpa, out, h.name, h.value);
        }
    }

    fn emitField(self: *EncoderContext, gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) Error!void {
        if (!hasUpper(name)) {
            return self.emitFieldLower(gpa, out, name, value);
        }
        var stack_buf: [256]u8 = undefined;
        if (name.len <= stack_buf.len) {
            for (name, 0..) |ch, i| stack_buf[i] = std.ascii.toLower(ch);
            return self.emitFieldLower(gpa, out, stack_buf[0..name.len], value);
        }
        const lname = try gpa.alloc(u8, name.len);
        defer gpa.free(lname);
        for (name, 0..) |ch, i| lname[i] = std.ascii.toLower(ch);
        return self.emitFieldLower(gpa, out, lname, value);
    }

    fn emitFieldLower(self: *EncoderContext, gpa: std.mem.Allocator, out: *std.ArrayList(u8), lname: []const u8, value: []const u8) Error!void {
        // 1. Sensitive fields MUST always be emitted as Never Indexed (0x10)
        //    and MUST NOT enter or match dynamic table values (RFC 7541 §7.1.3).
        if (isSensitiveLower(lname)) {
            const nidx = hp.StaticTable.findName(lname) orelse
                if (self.dyn.find(lname, "").name_only) |dn| static_len + 1 + dn else 0;
            return Encoder.emitLiteral(gpa, out, nidx, if (nidx == 0) lname else "", value, true);
        }

        // 2. Exact `(lname, value)` match in the static table (1-byte indexed).
        if (hp.StaticTable.findNameValue(lname, value)) |s_idx| {
            return Encoder.emitIndexed(gpa, out, s_idx);
        }

        // 3. Search connection dynamic table for full or name-only match.
        const dyn_match = self.dyn.find(lname, value);
        if (dyn_match.full) |d_idx| {
            return Encoder.emitIndexed(gpa, out, static_len + 1 + d_idx);
        }

        const nidx = hp.StaticTable.findName(lname) orelse
            if (dyn_match.name_only) |dn| static_len + 1 + dn else 0;

        // 4. CDN selective indexing: skip dynamic insertion for high-churn
        //    per-object fields or entries > 3/4 of `dyn.max_size`.
        const entry_size = (lname.len +| value.len) +| 32;
        const can_index = self.dyn.max_size >= 64 and
            entry_size <= (self.dyn.max_size * 3) / 4 and
            !shouldSkipIndexingLower(lname);

        if (!can_index) {
            return Encoder.emitLiteral(gpa, out, nidx, if (nidx == 0) lname else "", value, false);
        }

        // 6.2.1 Literal Header Field with Incremental Indexing (`0x40`, 6-bit prefix).
        // Emit using pre-insertion `nidx` FIRST, then insert into `self.dyn`.
        var buf: [10]u8 = undefined;
        const n = hp.encodeInteger(nidx, 6, &buf) catch unreachable;
        buf[0] |= 0x40;
        try out.appendSlice(gpa, buf[0..n]);
        if (nidx == 0) try hp.encodeStringShortest(lname, gpa, out);
        try hp.encodeStringShortest(value, gpa, out);
        try self.dyn.addWithAllocator(gpa, lname, value);
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
        // Sized for the widest u16 ("65535"): `status` comes from the handler
        // via `Response.status`, so a 4- or 5-digit code is a caller bug, not a
        // reason to hit `catch unreachable` and panic the connection.
        var sbuf: [5]u8 = undefined;
        const status_str = std.fmt.bufPrint(&sbuf, "{d}", .{status}) catch unreachable;
        if (hp.StaticTable.findNameValue(":status", status_str)) |idx| {
            try emitIndexed(arena, out, idx);
        } else {
            // name index 8 == ":status" (first :status entry in the static table).
            try emitLiteral(arena, out, 8, ":status", status_str, false);
        }

        for (headers) |h| {
            // RFC 9113 §8.2.2: drop connection-specific headers and any `te` on responses.
            if (isConnectionSpecific(h.name) or std.ascii.eqlIgnoreCase(h.name, "te")) continue;
            try emitField(arena, out, h.name, h.value);
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
        return encodeRequestEx(arena, out, method, scheme, path, authority, null, headers);
    }

    pub fn encodeRequestEx(
        arena: std.mem.Allocator,
        out: *std.ArrayList(u8),
        method: []const u8,
        scheme: []const u8,
        path: []const u8,
        authority: []const u8,
        protocol: ?[]const u8,
        headers: []const Header,
    ) Error!void {
        try emitPseudo(arena, out, ":method", method);
        if (protocol) |proto_val| try emitPseudo(arena, out, ":protocol", proto_val);
        try emitPseudo(arena, out, ":scheme", scheme);
        try emitPseudo(arena, out, ":path", path);
        if (authority.len > 0) try emitPseudo(arena, out, ":authority", authority);
        for (headers) |h| {
            // RFC 9113 §8.2.2: drop connection-specific headers; in requests
            // `te` is permitted only with token `trailers` (HTTP/1.1 input may
            // use mixed case or OWS — fold & normalize to lowercase "trailers").
            if (isConnectionSpecific(h.name)) continue;
            if (std.ascii.eqlIgnoreCase(h.name, "te")) {
                const trimmed = std.mem.trim(u8, h.value, " \t");
                if (!std.ascii.eqlIgnoreCase(trimmed, "trailers")) continue;
                try emitField(arena, out, "te", "trailers");
                continue;
            }
            try emitField(arena, out, h.name, h.value);
        }
    }

    /// Emits one pseudo-header: an indexed static entry when name+value match
    /// (e.g. `:method GET`), else a literal keyed on the pseudo name's index.
    fn emitPseudo(arena: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) Error!void {
        if (hp.StaticTable.findNameValue(name, value)) |idx| {
            try emitIndexed(arena, out, idx);
        } else {
            const nidx = hp.StaticTable.findName(name) orelse 0;
            try emitLiteral(arena, out, nidx, name, value, false);
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
            try emitField(arena, out, h.name, h.value);
        }
    }

    /// Emits a regular header field, avoiding lowercasing allocations whenever
    /// the name matches the static table, is already lowercase, or fits a small
    /// stack buffer. Marks sensitive headers as Never Indexed (RFC 7541 §6.2.3).
    fn emitField(arena: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) Error!void {
        const nidx = hp.StaticTable.findName(name) orelse 0;
        const never_index = isSensitiveHeader(name);
        if (nidx != 0) {
            try emitLiteral(arena, out, nidx, "", value, never_index);
            return;
        }
        if (!hasUpper(name)) {
            try emitLiteral(arena, out, 0, name, value, never_index);
            return;
        }
        var stack_buf: [256]u8 = undefined;
        if (name.len <= stack_buf.len) {
            for (name, 0..) |ch, i| stack_buf[i] = std.ascii.toLower(ch);
            try emitLiteral(arena, out, 0, stack_buf[0..name.len], value, never_index);
        } else {
            const lname = try lower(arena, name);
            try emitLiteral(arena, out, 0, lname, value, never_index);
        }
    }

    /// Encodes an HPACK Dynamic Table Size Update instruction (RFC 7541 §6.3,
    /// 5-bit prefix `001xxxxx`) into `buf` without allocation. Required at the
    /// start of the next header block after acknowledging a peer's reduced
    /// `SETTINGS_HEADER_TABLE_SIZE` (RFC 9113 §4.3.1 / RFC 7541 §4.2).
    pub fn encodeTableSizeUpdate(max_size: usize, buf: *[10]u8) []const u8 {
        const n = hp.encodeInteger(max_size, 5, buf) catch unreachable;
        buf[0] |= 0x20; // Dynamic Table Size Update flag (001xxxxx).
        return buf[0..n];
    }

    fn emitIndexed(arena: std.mem.Allocator, out: *std.ArrayList(u8), idx: usize) Error!void {
        var buf: [10]u8 = undefined;
        const n = hp.encodeInteger(idx, 7, &buf) catch unreachable;
        buf[0] |= 0x80; // Indexed Header Field flag.
        try out.appendSlice(arena, buf[0..n]);
    }

    /// Literal without Indexing (`0x00` pattern) or Never Indexed (`0x10`
    /// pattern, RFC 7541 §6.2.3). `name_idx == 0` ⇒ literal name.
    fn emitLiteral(
        arena: std.mem.Allocator,
        out: *std.ArrayList(u8),
        name_idx: usize,
        name: []const u8,
        value: []const u8,
        never_index: bool,
    ) Error!void {
        var buf: [10]u8 = undefined;
        const n = hp.encodeInteger(name_idx, 4, &buf) catch unreachable;
        if (never_index) buf[0] |= 0x10;
        try out.appendSlice(arena, buf[0..n]);
        // Shorter-of-two: Huffman-encode only when it is strictly smaller than
        // the raw octets (RFC 7541 §5.2); never larger than raw.
        if (name_idx == 0) try hp.encodeStringShortest(name, arena, out);
        try hp.encodeStringShortest(value, arena, out);
    }
};

fn hasUpper(s: []const u8) bool {
    for (s) |ch| if (std.ascii.isUpper(ch)) return true;
    return false;
}

fn lower(arena: std.mem.Allocator, s: []const u8) Error![]const u8 {
    const out = try arena.alloc(u8, s.len);
    for (s, 0..) |ch, i| out[i] = std.ascii.toLower(ch);
    return out;
}

/// Headers forbidden on HTTP/2 (RFC 9113 §8.2.2). Case-insensitive so callers
/// do not have to allocate a lowercased copy before filtering.
fn isConnectionSpecific(name: []const u8) bool {
    const banned = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (banned) |b| if (std.ascii.eqlIgnoreCase(name, b)) return true;
    return false;
}

/// Sensitive header fields emitted as Never Indexed (RFC 7541 §6.2.3) so
/// intermediaries do not compress secrets into shared dynamic tables.
fn isSensitiveHeader(name: []const u8) bool {
    const sensitive = [_][]const u8{ "authorization", "proxy-authorization", "cookie", "set-cookie" };
    for (sensitive) |s| if (std.ascii.eqlIgnoreCase(name, s)) return true;
    return false;
}

fn isSensitiveLower(lname: []const u8) bool {
    return switch (lname.len) {
        6 => std.mem.eql(u8, lname, "cookie"),
        10 => std.mem.eql(u8, lname, "set-cookie"),
        13 => std.mem.eql(u8, lname, "authorization"),
        19 => std.mem.eql(u8, lname, "proxy-authorization"),
        else => false,
    };
}

/// High-churn per-request / per-asset fields that should not evict stable site
/// and caching headers from a connection's 4 KiB HPACK dynamic table.
fn shouldSkipIndexingLower(lname: []const u8) bool {
    return switch (lname.len) {
        3 => std.mem.eql(u8, lname, "age"),
        4 => std.mem.eql(u8, lname, "etag"),
        5 => std.mem.eql(u8, lname, ":path") or std.mem.eql(u8, lname, "range"),
        8 => std.mem.eql(u8, lname, "if-range") or std.mem.eql(u8, lname, "location"),
        11 => std.mem.eql(u8, lname, "traceparent"),
        12 => std.mem.eql(u8, lname, "x-request-id"),
        13 => std.mem.eql(u8, lname, "content-range") or std.mem.eql(u8, lname, "if-none-match"),
        14 => std.mem.eql(u8, lname, "content-length"),
        17 => std.mem.eql(u8, lname, "if-modified-since"),
        else => false,
    };
}

// Thin wrappers so the rest of the file reads against local names. They rebuild
// the result into our own named structs (the codec returns anonymous struct
// types that don't coerce across a `catch`).
const IntResult = struct { value: u64, len: usize };
const StrResult = struct { value: []u8, len: usize };
const StrLenOnly = struct { decoded_len: usize, consumed: usize };
const StrScratch = struct { slice: []const u8, owned: ?[]u8, consumed: usize };

inline fn decInt(data: []const u8, prefix_bits: u4) Error!IntResult {
    const r = hp.decodeInteger(data, prefix_bits) catch return Error.Truncated;
    return .{ .value = r.value, .len = r.len };
}
inline fn decStr(data: []const u8, arena: std.mem.Allocator) !StrResult {
    const r = try hp.decodeString(data, arena);
    return .{ .value = r.value, .len = r.len };
}

fn decStrLenOnly(data: []const u8) Error!StrLenOnly {
    if (data.len == 0) return Error.Truncated;
    const huffman = (data[0] & 0x80) != 0;
    const len_res = hp.decodeInteger(data, 7) catch return Error.Truncated;
    const rem = data.len - len_res.len;
    if (len_res.value > rem) return Error.Truncated;
    const str_len: usize = @intCast(len_res.value);
    const total_len = len_res.len + str_len;
    const str_data = data[len_res.len..total_len];
    const dec_len = if (huffman)
        (hp.HuffmanCodec.decodeLengthOnly(str_data) catch return Error.Truncated)
    else
        str_len;
    return .{ .decoded_len = dec_len, .consumed = total_len };
}

fn decStrScratch(data: []const u8, scratch: []u8, gpa: std.mem.Allocator) Error!StrScratch {
    if (data.len == 0) return Error.Truncated;
    const huffman = (data[0] & 0x80) != 0;
    const len_res = hp.decodeInteger(data, 7) catch return Error.Truncated;
    const rem = data.len - len_res.len;
    if (len_res.value > rem) return Error.Truncated;
    const str_len: usize = @intCast(len_res.value);
    const total_len = len_res.len + str_len;
    const str_data = data[len_res.len..total_len];
    if (!huffman) {
        return .{ .slice = str_data, .owned = null, .consumed = total_len };
    }
    const r = hp.HuffmanCodec.decodeIntoScratch(str_data, scratch, gpa) catch |err| {
        return if (err == error.OutOfMemory) Error.OutOfMemory else Error.Truncated;
    };
    return .{ .slice = r.slice, .owned = r.owned, .consumed = total_len };
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

test "decode rejects an HPACK decompression bomb (bounded header-list size)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var block = std.ArrayList(u8).empty;
    defer block.deinit(testing.allocator);
    // Seed the dynamic table with a ~4KB entry: literal with incremental
    // indexing, name = static index 1 (":authority"), value = 4000 'a' bytes
    // (length 4000 as a 7-bit-prefix integer is 0x7f,0xA1,0x1E).
    try block.appendSlice(testing.allocator, &.{ 0x41, 0x7f, 0xA1, 0x1E });
    try block.appendNTimes(testing.allocator, 'a', 4000);
    // Then 140 one-byte indexed references (0x80|62) to that entry: ~570KB
    // decoded from 140 bytes on the wire — above the 512KB cap.
    try block.appendNTimes(testing.allocator, 0x80 | 62, 140);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    try testing.expectError(Error.HeaderListTooLarge, dec.decode(arena, block.items));
}

test "decode frees partial allocations when a block is malformed (no leak)" {
    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    // A valid indexed field (:method GET, both duped) followed by a literal
    // whose value string is truncated. The decoder allocated ":method", "GET",
    // and the literal name "a" before failing; all must be freed on the error
    // path or testing.allocator flags a leak.
    const block = [_]u8{ 0x82, 0x40, 0x01, 'a' };
    try testing.expectError(Error.Truncated, dec.decode(testing.allocator, &block));
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

test "decodeString rejects a length that would overflow the buffer bound" {
    // A 7-bit-prefix length of 2^64-1. The old bound was
    // `data.len < len_result.len + str_len`, whose add wraps here: the check
    // passed and the add itself panicked in safe builds.
    var buf: [16]u8 = undefined;
    const n = try hp.encodeInteger(std.math.maxInt(u64), 7, &buf);
    try testing.expectError(error.UnexpectedEof, hp.decodeString(buf[0..n], testing.allocator));
}

test "Decoder.decode survives a literal declaring a 2^64-1 string length" {
    // The whole server/client HEADERS path funnels through here, so this 12-byte
    // block — 00 7f 80 ff ff ff ff ff ff ff ff 01 — was a remote process abort
    // from a single unauthenticated frame.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    var lenbuf: [16]u8 = undefined;
    const n = try hp.encodeInteger(std.math.maxInt(u64), 7, &lenbuf);
    var block: [12]u8 = undefined;
    block[0] = 0x00; // literal without indexing, new (literal) name
    @memcpy(block[1 .. 1 + n], lenbuf[0..n]);
    try testing.expectError(Error.Truncated, dec.decode(arena_state.allocator(), block[0 .. 1 + n]));
}

test "decode frees the pending literal when the header-list cap trips (no leak)" {
    // The field that pushes the running total past max_list_size is decoded
    // (name + value allocated) before `account` rejects it. It must reach `out`
    // first, or decode's errdefer misses it — testing.allocator flags the leak.
    // The client decodes onto its gpa, so this leaked per rejected block there.
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 140) : (i += 1) {
        // Literal without indexing, new name: 0x00 | name "a" | value 4000*'v'
        // (4000 as a 7-bit-prefix integer is 0x7f,0xA1,0x1E). Each field is
        // 1 + 4000 + 32 = 4033 toward the 512KiB cap, so #131 trips it.
        try block.appendSlice(testing.allocator, &.{ 0x00, 0x01, 'a', 0x7f, 0xA1, 0x1E });
        try block.appendNTimes(testing.allocator, 'v', 4000);
    }
    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    try testing.expectError(Error.HeaderListTooLarge, dec.decode(testing.allocator, block.items));
}

test "encodeResponse tolerates a status code wider than three digits" {
    // `status` comes from the handler; a 4-digit code used to overflow the
    // format buffer and hit `catch unreachable`, panicking the connection.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    try Encoder.encodeResponse(arena, &out, 65535, &.{});

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqualStrings("65535", findHeader(hs, ":status").?);
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

test "Huffman decode rejects an unmatchable bit run instead of overflowing" {
    // Eight 0xFF bytes are 64 all-ones bits. No non-EOS code (and EOS itself)
    // ever matches, so the decoder would keep accumulating bits; bit_count is a
    // u6, so the 8th byte's `+= 8` overflowed 63→panic. It must now be rejected
    // as a decode error. Single unauthenticated HEADERS frame, remote crash.
    const bomb = @as([8]u8, @splat(0xFF));
    try testing.expectError(error.InvalidHuffmanCode, hp.HuffmanCodec.decode(&bomb, testing.allocator));
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

test "decode rejects dynamic table size update after a header field (RFC 7541 §4.2, #23)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    // Multiple dynamic table size updates at the start of a block are allowed.
    const valid = [_]u8{ 0x20, 0x3e, 0x82 }; // size=0, size=30, :method GET
    const hs = try dec.decode(arena, &valid);
    try testing.expectEqualStrings("GET", findHeader(hs, ":method").?);
    try testing.expectEqual(@as(usize, 30), dec.dyn.max_size);

    // Dynamic table size update after a header field is a decoding error.
    const invalid = [_]u8{ 0x82, 0x20 }; // :method GET, then size=0
    try testing.expectError(Error.InvalidTableSizeUpdate, dec.decode(testing.allocator, &invalid));
}

test "encodeTableSizeUpdate emits valid RFC 7541 §6.3 dynamic table size updates" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    var tsu_buf: [10]u8 = undefined;
    try out.appendSlice(arena, Encoder.encodeTableSizeUpdate(0, &tsu_buf));
    try testing.expectEqualSlices(u8, &[_]u8{0x20}, out.items);
    try Encoder.encodeResponse(arena, &out, 200, &.{.{ .name = "x-test", .value = "ok" }});

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    const hs = try dec.decode(arena, out.items);
    try testing.expectEqual(@as(usize, 0), dec.dyn.max_size);
    try testing.expectEqualStrings("200", findHeader(hs, ":status").?);
    try testing.expectEqualStrings("ok", findHeader(hs, "x-test").?);
}

test "Encoder filters te per RFC 9113 §8.2.2 and marks sensitive fields Never Indexed (#37, #41)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // encodeResponse drops ALL `te` headers (even `te: trailers`) and connection-specific headers.
    {
        var out: std.ArrayList(u8) = .empty;
        const headers = [_]Header{
            .{ .name = "TE", .value = "trailers" },
            .{ .name = "te", .value = "gzip" },
            .{ .name = "Connection", .value = "keep-alive" },
            .{ .name = "Set-Cookie", .value = "sid=secret" },
            .{ .name = "X-Mixed-Custom", .value = "ok" },
        };
        try Encoder.encodeResponse(arena, &out, 200, &headers);

        // `:status 200` is 0x88 (1 byte); next field is `set-cookie` (static 55 > 15),
        // emitted as Never Indexed (`0x10 | 0x0f = 0x1f`, followed by `55 - 15 = 40`).
        try testing.expectEqual(@as(u8, 0x88), out.items[0]);
        try testing.expectEqual(@as(u8, 0x1f), out.items[1]);
        try testing.expectEqual(@as(u8, 40), out.items[2]);

        var dec = Decoder.init(testing.allocator, 4096);
        defer dec.deinit();
        const hs = try dec.decode(arena, out.items);
        try testing.expectEqual(@as(?[]const u8, null), findHeader(hs, "te"));
        try testing.expectEqual(@as(?[]const u8, null), findHeader(hs, "connection"));
        try testing.expectEqualStrings("sid=secret", findHeader(hs, "set-cookie").?);
        try testing.expectEqualStrings("ok", findHeader(hs, "x-mixed-custom").?);
    }

    // encodeRequest retains `te: trailers` (folding case & OWS and normalizing to
    // lowercase "trailers") and drops multi-value or other transfer codings.
    {
        var out: std.ArrayList(u8) = .empty;
        const headers = [_]Header{
            .{ .name = "TE", .value = "gzip" },
            .{ .name = "te", .value = "Trailers" },
            .{ .name = "TE", .value = " \ttrailers " },
            .{ .name = "te", .value = "trailers, deflate" },
            .{ .name = "TE", .value = "trailers" },
            .{ .name = "Authorization", .value = "Bearer tok" },
        };
        try Encoder.encodeRequest(arena, &out, "POST", "https", "/rpc", "api.example.com", &headers);

        var dec = Decoder.init(testing.allocator, 4096);
        defer dec.deinit();
        const hs = try dec.decode(arena, out.items);
        var te_count: usize = 0;
        for (hs) |h| {
            if (std.mem.eql(u8, h.name, "te")) {
                try testing.expectEqualStrings("trailers", h.value);
                te_count += 1;
            }
        }
        try testing.expectEqual(@as(usize, 3), te_count);
        try testing.expectEqualStrings("Bearer tok", findHeader(hs, "authorization").?);
    }
}

test "StaticTable.findName bucket lookup matches linear scan for all entries (#41)" {
    for (hp.StaticTable.entries, 0..) |entry, i| {
        // Compute expected first-match 1-based index linearly.
        var expected: usize = i + 1;
        for (hp.StaticTable.entries[0..i], 0..) |prev, j| {
            if (std.mem.eql(u8, prev.name, entry.name)) {
                expected = j + 1;
                break;
            }
        }
        try testing.expectEqual(@as(?usize, expected), hp.StaticTable.findName(entry.name));

        // Verify case-insensitive match with uppercased name.
        var upper: [64]u8 = undefined;
        for (entry.name, 0..) |ch, k| upper[k] = std.ascii.toUpper(ch);
        try testing.expectEqual(@as(?usize, expected), hp.StaticTable.findName(upper[0..entry.name.len]));
    }
    try testing.expectEqual(@as(?usize, null), hp.StaticTable.findName(""));
    try testing.expectEqual(@as(?usize, null), hp.StaticTable.findName("x-not-in-static-table"));
    try testing.expectEqual(@as(?usize, null), hp.StaticTable.findName("way-longer-than-any-static-table-header-name-ever"));
}

test "DynamicTable ring buffer handles wrap-around, growth, eviction, and resize (#41)" {
    var dt = hp.DynamicTable.initWithSize(testing.allocator, 4096);
    defer dt.deinit();

    // Insert 40 entries (crosses initial 16 -> 32 -> 64 capacity doublings) and
    // verify newest-first indexing order.
    var kbuf: [16]u8 = undefined;
    var vbuf: [16]u8 = undefined;
    for (0..40) |i| {
        const k = std.fmt.bufPrint(&kbuf, "k-{d}", .{i}) catch unreachable;
        const v = std.fmt.bufPrint(&vbuf, "v-{d}", .{i}) catch unreachable;
        try dt.add(k, v);
    }
    try testing.expectEqual(@as(usize, 40), dt.len());
    try testing.expectEqualStrings("k-39", dt.get(0).?.name);
    try testing.expectEqualStrings("v-39", dt.get(0).?.value);
    try testing.expectEqualStrings("k-0", dt.get(39).?.name);
    try testing.expectEqual(@as(?hp.StaticTable.Entry, null), dt.get(40));

    // Shrink max_size to force FIFO eviction of oldest entries, then add more to wrap.
    dt.setMaxSize(256);
    try testing.expect(dt.current_size <= 256);
    const keep_newest = dt.get(0).?.name;
    try testing.expectEqualStrings("k-39", keep_newest);

    for (40..90) |i| {
        const k = std.fmt.bufPrint(&kbuf, "k-{d}", .{i}) catch unreachable;
        const v = std.fmt.bufPrint(&vbuf, "v-{d}", .{i}) catch unreachable;
        try dt.add(k, v);
        try testing.expect(dt.current_size <= 256);
        try testing.expectEqualStrings(k, dt.get(0).?.name);
    }

    // RFC 7541 §4.4: adding an entry larger than max_size empties the table.
    const huge = @as([300]u8, @splat('z'));
    try dt.add("x-big", &huge);
    try testing.expectEqual(@as(usize, 0), dt.len());
    try testing.expectEqual(@as(usize, 0), dt.current_size);
}

test "Encoder avoids temporary allocations when encoding into pre-sized buffer (#41)" {
    // Pre-size `out` on a tight FixedBufferAllocator; encoding static + mixed-case
    // custom headers with Huffman must succeed with zero extra heap allocations.
    var backing: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const alloc = fba.allocator();

    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(alloc, 256);
    const before = fba.end_index;

    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
        .{ .name = "Cache-Control", .value = "public, max-age=3600" },
        .{ .name = "X-Custom-Edge-Cache", .value = "HIT-aaaaaaaaaaaaaaaa" },
    };
    try Encoder.encodeResponse(alloc, &out, 200, &headers);
    // Zero extra allocations beyond the pre-allocated `out` capacity.
    try testing.expectEqual(before, fba.end_index);

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();
    var dec_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer dec_arena.deinit();
    const hs = try dec.decode(dec_arena.allocator(), out.items);
    try testing.expectEqualStrings("application/json; charset=utf-8", findHeader(hs, "content-type").?);
    try testing.expectEqualStrings("HIT-aaaaaaaaaaaaaaaa", findHeader(hs, "x-custom-edge-cache").?);
}

test "StaticTable.isStaticSlice and Decoder zero-copy static borrowing" {
    for (hp.StaticTable.entries) |e| {
        try testing.expect(isStaticSlice(e.name));
        try testing.expect(isStaticSlice(e.value));
    }
    try testing.expect(!isStaticSlice("outside-rodata"));

    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    // :method GET (0x82), :scheme https (0x87), :path / (0x84), literal static-name :authority = "cdn.example"
    const block = [_]u8{
        0x82, 0x87, 0x84, 0x01, 0x0b, 'c', 'd', 'n', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    };
    const hs = try dec.decode(testing.allocator, &block);
    defer freeHeaders(testing.allocator, hs);

    try testing.expect(isStaticSlice(hs[0].name));
    try testing.expect(isStaticSlice(hs[0].value));
    try testing.expect(isStaticSlice(hs[3].name));
    try testing.expect(!isStaticSlice(hs[3].value));
    try testing.expectEqualStrings("cdn.example", hs[3].value);
}

test "DynamicTable contiguous circular byte pool performs zero allocations in steady state" {
    var backing: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const alloc = fba.allocator();

    var dt = hp.DynamicTable.initWithSize(alloc, 256);
    defer dt.deinit();

    try dt.add("x-seed", "initial");
    const steady_mark = fba.end_index;

    var kbuf: [16]u8 = undefined;
    var vbuf: [32]u8 = undefined;
    for (0..200) |i| {
        const k = std.fmt.bufPrint(&kbuf, "x-hdr-{d}", .{i}) catch unreachable;
        const v = std.fmt.bufPrint(&vbuf, "val-{d}-payload", .{i}) catch unreachable;
        try dt.add(k, v);
        try testing.expectEqual(steady_mark, fba.end_index);
        const top = dt.get(0).?;
        try testing.expectEqualStrings(k, top.name);
        try testing.expectEqualStrings(v, top.value);
    }
}

test "Decoder.decodeDiscard synchronizes dynamic table and rejects bombs with zero output allocs" {
    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    var enc = EncoderContext.initWithMaxSize(4096);
    defer enc.deinit(testing.allocator);

    // Block 1 (refused stream): seeds dynamic table via EncoderContext.
    var b1: std.ArrayList(u8) = .empty;
    defer b1.deinit(testing.allocator);
    try enc.encodeRequest(testing.allocator, &b1, "GET", "https", "/refused", "edge.cdn.test", &.{
        .{ .name = "x-cdn-pop", .value = "hkg-01" },
        .{ .name = "user-agent", .value = "zig-cdn-bench/2.0" },
    });
    try dec.decodeDiscard(b1.items);

    // Block 2 (accepted stream): references dynamic indices from Block 1!
    var b2: std.ArrayList(u8) = .empty;
    defer b2.deinit(testing.allocator);
    try enc.encodeRequest(testing.allocator, &b2, "GET", "https", "/accepted", "edge.cdn.test", &.{
        .{ .name = "x-cdn-pop", .value = "hkg-01" },
        .{ .name = "user-agent", .value = "zig-cdn-bench/2.0" },
    });
    try testing.expect(b2.items.len < b1.items.len);

    const hs = try dec.decode(testing.allocator, b2.items);
    defer freeHeaders(testing.allocator, hs);
    try testing.expectEqualStrings("edge.cdn.test", findHeader(hs, ":authority").?);
    try testing.expectEqualStrings("hkg-01", findHeader(hs, "x-cdn-pop").?);
    try testing.expectEqualStrings("zig-cdn-bench/2.0", findHeader(hs, "user-agent").?);
}

test "EncoderContext compresses repeatable CDN headers, skips high-churn fields, and emits RFC 7541 §4.2 TSUs" {
    var enc = EncoderContext.initWithMaxSize(4096);
    defer enc.deinit(testing.allocator);
    var dec = Decoder.init(testing.allocator, 4096);
    defer dec.deinit();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const resp_headers = [_]Header{
        .{ .name = "Server", .value = "zig-cdn-edge/2.0" },
        .{ .name = "Cache-Control", .value = "public, max-age=31536000, immutable" },
        .{ .name = "Strict-Transport-Security", .value = "max-age=63072000; includeSubDomains" },
        .{ .name = "ETag", .value = "\"obj-1\"" }, // high-churn -> not indexed
        .{ .name = "Set-Cookie", .value = "sid=topsecret" }, // sensitive -> Never Indexed (0x10)
    };

    var out1: std.ArrayList(u8) = .empty;
    defer out1.deinit(testing.allocator);
    try enc.encodeResponse(testing.allocator, &out1, 200, &resp_headers, 1024);
    const hs1 = try dec.decode(arena, out1.items);
    try testing.expectEqualStrings("zig-cdn-edge/2.0", findHeader(hs1, "server").?);
    try testing.expectEqualStrings("1024", findHeader(hs1, "content-length").?);

    // ETag and Content-Length must NOT have entered the encoder's dynamic table,
    // while Server, Cache-Control, and Strict-Transport-Security MUST be indexed (3 entries).
    try testing.expectEqual(@as(usize, 3), enc.dyn.len());

    var out2: std.ArrayList(u8) = .empty;
    defer out2.deinit(testing.allocator);
    try enc.encodeResponse(testing.allocator, &out2, 200, &resp_headers, 2048);
    // Second response compresses the 3 long headers to 3 single-byte indices!
    try testing.expect(out2.items.len * 2 < out1.items.len);
    const hs2 = try dec.decode(arena, out2.items);
    try testing.expectEqualStrings("public, max-age=31536000, immutable", findHeader(hs2, "cache-control").?);
    try testing.expectEqualStrings("sid=topsecret", findHeader(hs2, "set-cookie").?);
    try testing.expectEqualStrings("2048", findHeader(hs2, "content-length").?);

    // Simulate peer shrinking SETTINGS_HEADER_TABLE_SIZE to 64 then raising to 2048:
    // RFC 7541 §4.2 requires emitting TSU(64) followed by TSU(2048) on next block.
    enc.notePeerHeaderTableSize(64, 64);
    enc.notePeerHeaderTableSize(2048, 2048);

    var out3: std.ArrayList(u8) = .empty;
    defer out3.deinit(testing.allocator);
    try enc.encodeResponse(testing.allocator, &out3, 204, &.{.{ .name = "x-after", .value = "resize" }}, null);
    // TSU(64): 0x20 | 31 = 0x3f, 64 - 31 = 33 (0x21)
    try testing.expectEqual(@as(u8, 0x3f), out3.items[0]);
    try testing.expectEqual(@as(u8, 33), out3.items[1]);
    const hs3 = try dec.decode(arena, out3.items);
    try testing.expectEqual(@as(usize, 2048), dec.dyn.max_size);
    try testing.expectEqualStrings("204", findHeader(hs3, ":status").?);
    try testing.expectEqualStrings("resize", findHeader(hs3, "x-after").?);
}
