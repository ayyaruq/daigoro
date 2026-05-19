const std = @import("std");

pub fn build(b: *std.Build) void {
    const zon = @import("build.zig.zon");
    const version = comptime try std.SemanticVersion.parse(zon.version);

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
        .version = version,
    });

    // The C header is not generated; it is maintained by hand alongside the Zig source and must be kept in sync manually.
    // The install step copies it to zig-out/include/ so that cgo can find it.
    lib.installHeader(b.path("include/daigoro.h"), "daigoro.h");

    // Make the library file and docs available in zig-out/lib/
    b.installArtifact(lib);

    // Install docs
    const docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate API documentation");
    docs_step.dependOn(&docs.step);
    b.getInstallStep().dependOn(docs_step);

    // Unit tests
    const tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Integration tests require an explicit -Dexe=path to ffxiv_dx11.exe to don't run automatically
    const integration_step = b.step("integration", "Run integration tests against the game binary");
    if (b.top_level_steps.contains("integration")) {
        const exe = b.option([]const u8, "exe", "Path to ffxiv_dx11.exe for integration tests");
        const opts = b.addOptions();
        opts.addOption(?[]const u8, "exe_path", exe);

        const integration_mod = b.createModule(.{
            .root_source_file = b.path("tests/integration_e2e.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "daigoro", .module = lib_mod },
                .{ .name = "build_options", .module = opts.createModule() },
            },
        });

        // Add the Zig tests
        const z_test = b.addTest(.{
            .root_module = integration_mod,
        });
        const run_z = b.addRunArtifact(z_test);
        integration_step.dependOn(&run_z.step);

        // Add C tests
        const c_test = b.addExecutable(.{
            .name = "integration_e2e_c",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
            }),
        });
        c_test.addCSourceFile(.{
            .file = b.path("tests/integration_e2e.c"),
        });
        c_test.addIncludePath(b.path("include"));
        c_test.linkLibrary(lib);

        // Needed for mkdtemp
        c_test.root_module.addCMacro("_POSIX_C_SOURCE", "200809L");
        if (target.result.os.tag == .macos) {
            c_test.root_module.addCMacro("_DARWIN_C_SOURCE", "1");
        }
        if (exe) |exe_path| {
            c_test.root_module.addCMacro("EXE_PATH", b.fmt("\"{s}\"", .{exe_path}));
        } else {
            // Define an extra macro so C code can check `#ifdef EXE_PATH_MISSING` and fail compilation properly
            c_test.root_module.addCMacro("EXE_PATH_MISSING", "1");
        }

        const run_c = b.addRunArtifact(c_test);
        integration_step.dependOn(&run_c.step);
    }
}
