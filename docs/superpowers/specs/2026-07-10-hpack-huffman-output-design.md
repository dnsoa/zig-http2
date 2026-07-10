# 设计:HPACK 输出 Huffman 压缩(择短)

- 日期:2026-07-10
- 对应 review 项:🟢「输出无 HPACK/Huffman 压缩」
- 目标库:`zig-http2`(gRPC / 自研 CDN 的 HTTP/2 底座)

## 背景

`hpack.zig` 的 `Encoder` 目前对所有字面 name/value 都以**原始**(非 Huffman)形式发出:`emitLiteral` 调 `hp.encodeString(str, false, ...)`。对高频 gRPC 调用 / CDN 响应,头部值(如 `content-type: application/grpc`、`date`、`server`、URL path、user-agent)每次全量字面量,浪费带宽。解码侧早已支持 Huffman(`decodeString` 按 H 位自动解),`HuffmanCodec.encode/decode` 往返也已有测试——只差编码侧启用。

## 决策

- **择短(shorter-of-two)**:每个字面串,Huffman 编码**当且仅当它严格更短**(`huffmanLen(s) < s.len`)。RFC 7541 允许任一形式;择短最优且**永不比原始更大**。不取"总是 Huffman"(对高熵值会变长)。
- **单一 choke point**:只改 `emitLiteral`,自动覆盖 `encodeResponse`(server 响应)/ `encodeRequest`(client 请求)/ `encodeTrailers`(gRPC trailers)/ `emitPseudo` / `:status` 字面路径。
- 用长度预判(`huffmanLen`)决定,避免在不采用 Huffman 时白白分配编码缓冲。

## 已核实锚点

- `Encoder.emitLiteral`(`hpack.zig:215-228`):`if (name_idx == 0) encodeString(name,false,…); encodeString(value,false,…)` —— name(仅字面时)与 value 都过这里。所有编码路径最终都调 `emitLiteral`。
- `hp.encodeString(str, use_huffman, alloc, out)`(`hpack_codec.zig`):`use_huffman` 为真时调 `HuffmanCodec.encode` 并置长度前缀的 H 位(0x80);为假时原始。**无需改此函数**,只需正确传 `use_huffman`。
- `HuffmanCodec.lengths: [256]u5`(`hpack_codec.zig`):RFC 7541 Appendix B 每字节码长(bit)。`huffmanLen` 据此累加。
- 解码侧无需任何改动。

## 变更

### 1) `hpack_codec.zig`:Huffman 编码长度
```zig
/// Byte length `str` would occupy Huffman-encoded (RFC 7541 §5.2: bit length
/// rounded up to whole bytes; the EOS padding fills the final partial byte).
pub fn huffmanLen(str: []const u8) usize {
    var bits: usize = 0;
    for (str) |b| bits += HuffmanCodec.lengths[b];
    return (bits + 7) / 8;
}
```
(放在 `HuffmanCodec` 之后或模块级;`lengths` 在 `HuffmanCodec` 内,若作模块级函数则用 `HuffmanCodec.lengths`。)

### 2) `hpack.zig`:`emitLiteral` 择短
```zig
fn emitLiteral(arena, out, name_idx, name, value) Error!void {
    ... 现有 name_idx 整数前缀 ...
    if (name_idx == 0) {
        try hp.encodeString(name, hp.huffmanLen(name) < name.len, arena, out);
    }
    try hp.encodeString(value, hp.huffmanLen(value) < value.len, arena, out);
}
```

其余 Encoder 代码不变。

## 测试

现有编码测试均为**语义往返**(decode 后比对 value)或纯 decode,不断言精确字节或"无 H 位",故启用 Huffman 后**继续通过**(解码器两种都认)。

新增(用 `std.mem.indexOf` 断言编码输出**包含**期望形式,避免脆弱的偏移解析):
1. **可压缩值走 Huffman 且往返正确**:`encodeResponse` 编码含一个可压缩 value 的头(如 `value = "aaaaaaaaaaaaaaaa"`,'a' 为 5 bit → Huffman 明显更短)。另用 `hp.encodeString(value, true, …)` 算出期望的 **Huffman 串**(含 H 位长度前缀),断言 `std.mem.indexOf(out.items, expected_huffman) != null`;再 decode 回,断言 value 原样。
2. **不可压缩值保持原始**:选一个 Huffman **不更短** 的 value(如 `"\x00"` —— 0x00 码长 13 bit → `huffmanLen=2 > 1`,择短判定为原始)。用 `hp.encodeString(value, false, …)` 算出期望的**原始串**(含无 H 位长度前缀),断言 `indexOf(out.items, expected_raw) != null`;decode 回原样。
3. **`huffmanLen` 边界**:空串 → 0;已知串(如 `"aaaa"` = ceil(4×5/8)=3;`"\x00"` = ceil(13/8)=2)的期望字节数。
4. **字面 name 侧也择短(守住 choke point 承诺)**:`encodeResponse` 编码一个**名字不在静态表**、且可压缩的小写头名(如 `name = "x-custom-long-header-name"`,→ `name_idx==0` 走字面 name 路径),值取短固定值(如 `"1"`,择短判定为原始,隔离出 name)。用 `hp.encodeString(name, true, …)` 算期望的 **name Huffman 串**,断言 `indexOf(out.items, expected) != null`;decode 回断言 name/value 原样。旧代码 name 发原始 → 此用例亦红,防"只改 value 漏 name"。

回归:`encode/decode response round trip`、`encodeTrailers`、`encodeRequest`、`encode non-static status`、gRPC echo、raw round-trip 全过。

## 风险

极低:解码侧零改动;`HuffmanCodec` 往返已测;择短保证永不膨胀;唯一新逻辑是 `huffmanLen` 与 `<` 判定。CPU:采用 Huffman 时多一次 O(n) 长度预扫(不采用时不分配),头部串短,开销可忽略。

## 落地(单 Task、TDD)

单 Task:`huffmanLen` + `emitLiteral` 择短(name+value 两侧)+ 新测试 1/2/3/4。测试 3 引用 `huffmanLen`(旧代码无此符号,不加则不编译),故先加 `huffmanLen`,再加四个测试(此时 test 1(value)与 test 4(name)因 `emitLiteral` 仍发原始而失败=红、test 2/3 基线过),再改 `emitLiteral` 两侧择短使 1/4 转绿,跑全绿。
