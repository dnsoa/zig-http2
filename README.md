# zig-http2

A dependency-free, transport-agnostic HTTP/2 (RFC 9113) and HPACK (RFC 7541) server and client library for Zig `0.17.0`'s `std.Io` model.

## Features

- **Transport-agnostic**: Runs over any `*std.Io.Reader` / `*std.Io.Writer` pair (TLS-wrapped sockets, TCP, Unix sockets, in-memory pipes).
- **Server & Client**: Full multiplexed HTTP/2 framing, stream & connection flow control, trailers, streaming request/response bodies (`ctx.body_reader`), and bidirectional streaming (gRPC-ready).
- **HPACK (RFC 7541)**: Separate decoder/encoder direction split with dynamic table ring buffer, Huffman shorter-of-two encoding, Never-Indexed marking for sensitive headers (`authorization`, `cookie`, `set-cookie`, `proxy-authorization`), and decompression-bomb limits (`SETTINGS_MAX_HEADER_LIST_SIZE`).
- **Hardened & RFC 9113 compliant**:
  - Strict header/pseudo-header/content-length validation and `cookie` joining.
  - Protections against Rapid Reset (CVE-2023-44487), CONTINUATION floods (CVE-2024-27316), and control-frame / empty-DATA floods (CVE-2019-9512 / 9515 / 9518).
  - Bounded circular request body buffer (`O(initial_window_size)`).
  - Per-RPC deadlines (`ctx.setDeadline` / `ctx.setDeadlineIn`), graceful shutdown (`Server.requestStop()` + `drain_timeout_ms`), and client keepalive PINGs.

## Requirements

- **Zig `0.17.0`** (uses `std.Io`, `@backingInt`, and `std.process.Init`).

## Installation

Fetch the package with `zig fetch`:

```sh
zig fetch --save https://github.com/dnsoa/zig-http2/archive/refs/tags/v0.2.0.tar.gz
```

Then wire the `zig_http2` module in your `build.zig`:

```zig
const h2_dep = b.dependency("zig_http2", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_http2", h2_dep.module("zig_http2"));
```

## Quick Start

### Server

```zig
const h2 = @import("zig_http2");

fn handler(ctx: *h2.Context) anyerror!void {
    try ctx.res.send(200, "text/plain", "hello");
}

var srv: h2.Server = .{
    .io = io,
    .gpa = gpa,
    .handler = handler,
};

// Call per accepted connection (e.g. after TLS ALPN negotiates "h2"):
h2.serveConn(&srv, &reader, &writer, client_ip, "https");

// For graceful shutdown (wakes idle connections immediately):
srv.requestStop();
```

### Client

```zig
const std = @import("std");
const h2 = @import("zig_http2");

var client: h2.Client = undefined;
try client.initWithConfig(io, gpa, &reader, &writer, .{
    .connection_window_size = 1 << 20,
    .initial_window_size = 1 << 20,
    .keepalive_time_ms = 30_000,
    .keepalive_timeout_ms = 10_000,
});
defer client.deinit();

const stream = try client.openStream(.{
    .method = "POST",
    .path = "/echo",
    .authority = "example.com",
}, false);
defer stream.close();

try stream.send("hello over h2", true);

while (true) {
    const ev = stream.readEvent(arena) catch |err| switch (err) {
        error.EndOfStream => break,
        else => return err,
    };
    switch (ev) {
        .headers => |h| if (h.end_stream) break,
        .data => |d| if (d.end_stream) break,
        .rst, .goaway => break,
    }
}
```

> **Note**: Always call `stream.close()` when finished with a `*h2.Stream` so completed streams are reclaimed on long-lived connections.

## Building & Testing

```sh
# Run unit & integration test suite (Debug / ReleaseSafe)
zig build test
zig build test -Doptimize=ReleaseSafe

# Build and run the end-to-end example (server + client over AF_UNIX socketpair)
zig build example
./zig-out/bin/zig-http2-example
```

## License

[MIT](LICENSE)
