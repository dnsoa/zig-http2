# HPACK 输出 Huffman 压缩 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** HPACK 编码器对字面 name/value 择短使用 Huffman(仅当更短),压缩 gRPC/CDN 头部输出;解码侧无需改动。

**Architecture:** 新增 `hp.huffmanLen(str)` 计算 Huffman 编码字节数;`Encoder.emitLiteral`(所有编码路径的字面串 choke point)对 name(仅 `name_idx==0` 时字面)与 value 各自 `use_huffman = hp.huffmanLen(s) < s.len`,传给现有 `hp.encodeString`。

**Tech Stack:** Zig 0.16.0,`std.Io`,无第三方依赖。

**Spec:** `docs/superpowers/specs/2026-07-10-hpack-huffman-output-design.md`

## Global Constraints

- Zig 0.16.0;仅用 `std`;改动限于 `src/hpack_codec.zig`(加 `huffmanLen`)与 `src/hpack.zig`(改 `emitLiteral` + 测试)。
- **择短**:Huffman 当且仅当 `huffmanLen(s) < s.len`(严格更短);永不比原始更大。
- 单一 choke point:只改 `emitLiteral`,覆盖 `encodeResponse`/`encodeRequest`/`encodeTrailers`/`emitPseudo`/`:status` 字面路径;name(字面时)与 value 两侧都择短。
- 解码侧零改动(`decodeString` 按 H 位自动解)。
- `zig build test --summary all` 全绿(现状 57/57 + 新增 4 用例);`zig fmt --check` clean;伪 "failed command … --listen=-" 行忽略,以 "Build Summary" 为准。

---

### Task 1: 择短 Huffman 输出

**Files:**
- Modify: `src/hpack_codec.zig`(新增模块级 `huffmanLen`)
- Modify: `src/hpack.zig`(`emitLiteral` 择短;`test` 区加 4 用例)

**Interfaces (Produces):**
- `pub fn huffmanLen(str: []const u8) usize`(`hpack_codec.zig`,经 `hpack.zig` 的 `hp` 别名调用:`hp.huffmanLen`)

- [ ] **Step 1: 加 `huffmanLen`(让测试可编译)**

在 `src/hpack_codec.zig` 的 `HuffmanCodec` 结构定义之后(模块级)新增:

```zig
/// Byte length `str` would occupy Huffman-encoded (RFC 7541 §5.2): the sum of
/// per-symbol code lengths in bits, rounded up to whole bytes (the EOS padding
/// fills the final partial byte). Cheap O(n) scan, no allocation — used to
/// decide whether Huffman is shorter than the raw string before encoding.
pub fn huffmanLen(str: []const u8) usize {
    var bits: usize = 0;
    for (str) |b| bits += HuffmanCodec.lengths[b];
    return (bits + 7) / 8;
}
```

- [ ] **Step 2: 加 4 个测试**

在 `src/hpack.zig` 的 `test` 区(现有编码测试附近)追加。`Header`/`Encoder`/`Decoder`/`hp`/`findHeader`/`testing` 均在作用域:

```zig
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
```

- [ ] **Step 3: 跑测试确认红**

Run: `zig build test --summary all`
Expected: FAIL —— `huffmanLen` 用例与 `keeps a value raw` 用例通过(基线),但 `uses Huffman for a value` 与 `uses Huffman for a literal header name` **失败**:此时 `emitLiteral` 仍以原始形式发出,输出不含 value/name 的 Huffman 串,`indexOf` 返回 null。

- [ ] **Step 4: 实现 `emitLiteral` 择短**

把 `src/hpack.zig` 的 `emitLiteral` 末尾两行:

```zig
        if (name_idx == 0) try hp.encodeString(name, false, arena, out);
        try hp.encodeString(value, false, arena, out);
```
替换为:

```zig
        // Shorter-of-two: Huffman-encode only when it is strictly smaller than
        // the raw octets (RFC 7541 §5.2); never larger than raw.
        if (name_idx == 0) try hp.encodeString(name, hp.huffmanLen(name) < name.len, arena, out);
        try hp.encodeString(value, hp.huffmanLen(value) < value.len, arena, out);
```

- [ ] **Step 5: 跑全套测试**

Run: `zig build test --summary all`
Expected: PASS —— 4 个新用例全绿,现有 57 个回归全过(共 61/61)。`zig fmt --check src/hpack.zig src/hpack_codec.zig` clean。

- [ ] **Step 6: Commit**

```bash
git add src/hpack.zig src/hpack_codec.zig
git commit -m "hpack: Huffman-encode literal names/values when shorter"
```

---

## Self-Review

**Spec coverage:**
- `huffmanLen`(bit 累加 / 向上取整字节)→ Step 1 ✓
- `emitLiteral` name+value 两侧择短 → Step 4 ✓
- 单 choke point 覆盖所有编码路径 → 通过 `emitLiteral` ✓
- 测试:value Huffman(1)、value 原始(2)、`huffmanLen` 边界(3)、literal name Huffman(4)→ Step 2 ✓
- 解码侧零改动 ✓

**Placeholder scan:** 无 TBD;每步完整可粘贴代码。

**Type consistency:**
- `hp.huffmanLen(str: []const u8) usize` 定义(Step 1)与引用(Step 2 测试、Step 4 emitLiteral)一致。
- `hp.encodeString(str, use_huffman: bool, arena, out)`、`Encoder.encodeResponse`、`Decoder.decode`、`findHeader`、`Header` 均为现有 API,签名不变。
- `HuffmanCodec.lengths` 为 `[256]u5`,`for (str) |b| bits += HuffmanCodec.lengths[b]`(`b: u8` 索引)合法。
