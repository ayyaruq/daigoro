const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{
        .whitelist = &.{
            .{ .cpu_arch = .x86_64, .os_tag = .linux },
            .{ .cpu_arch = .x86_64, .os_tag = .macos },
            .{ .cpu_arch = .x86_64, .os_tag = .freebsd },
        },
    });

    // Check the arch tag
    if (target.result.cpu.arch != .x86_64) {
        const arch_fail_step = b.addFail(b.fmt("Architecture '{s}' is not supported. This project requires x86_64 for win64 ABI compatibility.", .{@tagName(target.result.cpu.arch)}));
        b.getInstallStep().dependOn(&arch_fail_step.step);
    }

    // Check the OS tag
    if (target.result.os.tag == .windows) {
        // b.fail stops the build and prints the message cleanly
        const win_fail_step = b.addFail("This project cannot be built for Windows. It is designed to run PE logic on Unix-like systems.");
        b.getInstallStep().dependOn(&win_fail_step.step);
    }

    // ReleaseSafe keeps bounds checks and overflow detection active, which matters here because we're doing a lot of
    // raw pointer arithmetic over memory we loaded from an external binary. ReleaseFast would remove those guards and
    // turn bugs into undefined behaviour silently.
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });

    // Actual shared lib export for C-ABI consumers
    const lib = b.addLibrary(.{
        .name = "daigoro",
        .linkage = .static,
        .root_module = lib_mod,
    });

    // The C header is not generated; it is maintained by hand alongside the Zig source and must be kept in sync manually.
    // The install step copies it to zig-out/include/ so that cgo can find it.
    lib.installHeader(b.path("include/daigoro.h"), "daigoro.h");

    // Make the library file and docs available in zig-out/lib/
    b.installArtifact(lib);
}
