const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The public library module. Consumers do
    //   b.dependency("zig_http2", .{}).module("zig_http2")
    // and then `@import("zig_http2")`.
    const mod = b.addModule("zig_http2", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ---- `zig build test` ----
    // lib.zig's top-level `test` block pulls in every internal module so all of
    // their `test` blocks run from one runner.
    const test_step = b.step("test", "Run unit tests");
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(b.addTest(.{ .root_module = test_mod }));
    test_step.dependOn(&run_tests.step);

    // ---- `zig build example` ----
    // A tiny h2 server + client talking over a plain socketpair (no TLS), to
    // sanity-check the public API end to end.
    const example_mod = b.createModule(.{
        .root_source_file = b.path("src/example.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_mod.addImport("zig_http2", mod);
    const example_exe = b.addExecutable(.{ .name = "zig-http2-example", .root_module = example_mod });
    b.installArtifact(example_exe);
    const example_step = b.step("example", "Build the example (server + client over a socketpair)");
    example_step.dependOn(&example_exe.step);
}
