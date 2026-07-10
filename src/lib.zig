//! zig-http2 — a dependency-free HTTP/2 (RFC 7540) server and client for Zig
//! 0.16's `std.Io` model. Transport-agnostic: callers supply any
//! `*std.Io.Reader`/`*std.Io.Writer` pair (e.g. a TLS-wrapped socket).
//!
//! Quick start:
//!   ```zig
//!   const h2 = @import("zig_http2");
//!
//!   // Server: fill a `h2.Server` and call `h2.serveConn` per connection.
//!   fn handler(ctx: *h2.Context) anyerror!void {
//!       try ctx.res.send(200, "text/plain", "hello");
//!   }
//!   var srv: h2.Server = .{ .io = io, .gpa = gpa, .handler = handler };
//!   h2.serveConn(&srv, &reader, &writer, null, "https");
//!
//!   // Client: wrap a transport, open a stream, send + read.
//!   var c: h2.Client = undefined;
//!   try c.init(io, gpa, &reader, &writer);
//!   defer c.deinit();
//!   const s = try c.openStream(.{ .path = "/svc/Echo" }, false);
//!   try s.send("ping", true);
//!   // s.readEvent(arena) yields .headers / .data / .rst / .goaway
//!   ```
//!
//! gRPC readiness: trailers, streaming request bodies (`ctx.body_reader`), and
//! bidirectional streaming (separate send/receive threads) are supported — the
//! shapes a gRPC server/client needs. See README for the client's v1 limits.

const types = @import("types.zig");
pub const proto = @import("proto.zig");
pub const hpack = @import("hpack.zig");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");

// Top-level convenience re-exports.
pub const Header = types.Header;
pub const Request = types.Request;
pub const Response = types.Response;
pub const Sink = types.Sink;
pub const Context = types.Context;
pub const BodyReader = types.BodyReader;
pub const Handler = types.Handler;

pub const Server = server_mod.Server;
pub const Config = server_mod.Config;
pub const serveConn = server_mod.serveConn;

pub const Client = client_mod.Client;
pub const RequestHead = client_mod.RequestHead;
pub const Event = client_mod.Event;

pub const ErrorCode = proto.ErrorCode;

test {
    // Reference every internal module so its `test` blocks run from this root.
    _ = types;
    _ = proto;
    _ = hpack;
    _ = server_mod;
    _ = client_mod;
}
