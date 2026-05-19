const std = @import("std");
const Context = @import("daigoro").Context;

const exe_path = @import("build_options").exe_path;

comptime {
    if (exe_path == null) {
        @compileError("Integration tests require a path. Run with: zig build integration -Dexe=\"/path/to/ffxiv_dx11.exe\"");
    }
}

const exe = exe_path.?;

test "encode/decode round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cache_dir = try tmp.dir.realpath(".", &abs_buf);

    var ctx = try Context.init(exe, cache_dir);
    defer ctx.deinit();

    const original = "Oodle" ** 200;
    const max_compressed = ctx.maxCompressedSize(original.len) * 2;
    const compressed_buf = try std.testing.allocator.alloc(u8, max_compressed);
    defer std.testing.allocator.free(compressed_buf);

    const written = try ctx.encode(original.ptr, original.len, compressed_buf.ptr, max_compressed);

    const decompressed_buf = try std.testing.allocator.alloc(u8, original.len);
    defer std.testing.allocator.free(decompressed_buf);
    try ctx.decode(compressed_buf.ptr, @intCast(written), decompressed_buf.ptr, original.len);

    try std.testing.expectEqualSlices(u8, original, decompressed_buf);
}

test "rejects double init" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cache_dir = try tmp.dir.realpath(".", &abs_buf);

    var ctx = try Context.init(exe, cache_dir);
    defer ctx.deinit();

    try std.testing.expectError(error.AlreadyInitialised, Context.init(exe, cache_dir));
}

test "re-init after destroy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cache_dir = try tmp.dir.realpath(".", &abs_buf);

    var ctx = try Context.init(exe, cache_dir);
    ctx.deinit();

    // Re-init after deinit succeeds
    var ctx2 = try Context.init(exe, cache_dir);
    defer ctx2.deinit();
    try std.testing.expect(ctx2.maxCompressedSize(100) > 0);
}
