const std = @import("std");
const xxh3 = std.hash.XxHash3;
const b62 = @import("base62.zig");
const ffxiv = @import("ffxiv.zig");

const CACHE_VERSION = "v1";

// Serialised RVAs - offsets from image base, no raw pointers (not actually extern, just for layout enforcement)
pub const CacheEntry = extern struct {
    hash: u64,
    htbits: i32,
    window: i32,
    shared_size: u32,
    set_malloc_free: u32,
    shared_set_win: u32,
    udp_state_size: u32,
    udp_train: u32,
    udp_decode: u32,
    udp_encode: u32,
    alloca_probe: u32,

    comptime {
        // hash(8) + 2x i32(8) + 8x u32(32)
        if (@sizeOf(CacheEntry) != 48) {
            @compileError("CacheEntry size changed from 48 bytes: the cache file format is incompatible.");
        }
        // hash(8) needs 8 byte alignment
        if (@alignOf(CacheEntry) != 8) {
            @compileError("CacheEntry alignment changed from 8: serialised cache files will have different padding on disk.");
        }
    }
};

pub fn hashFile(data: []const u8) u64 {
    var hasher = xxh3.init(0);
    hasher.update(data);
    return hasher.final();
}

// Attempts to read a cached signature set for the given hash.
// Returns null on any miss (file absent, hash mismatch, truncated data).
pub fn load(cache_dir: ?[]const u8, hash: u64) ?CacheEntry {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = resolvePath(cache_dir, hash, &path_buf) catch return null;
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    var data: [@sizeOf(CacheEntry)]u8 align(@alignOf(CacheEntry)) = undefined;
    const read_size = file.readAll(&data) catch return null;
    if (read_size != @sizeOf(CacheEntry)) return null;

    const entry = std.mem.bytesAsValue(CacheEntry, &data);
    if (entry.hash != hash) return null;
    return entry.*;
}

// Persists a signature set under the given hash.
pub fn save(cache_dir: ?[]const u8, hash: u64, exe: ffxiv) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try resolvePath(cache_dir, hash, &path_buf);

    const entry = CacheEntry{
        .hash = hash,
        .htbits = exe.htbits,
        .window = exe.window,
        .shared_size = @truncate(@intFromPtr(exe.shared_size) - exe.base_address),
        .set_malloc_free = @truncate(@intFromPtr(exe.set_malloc_free) - exe.base_address),
        .shared_set_win = @truncate(@intFromPtr(exe.shared_set_win) - exe.base_address),
        .udp_state_size = @truncate(@intFromPtr(exe.udp_state_size) - exe.base_address),
        .udp_train = @truncate(@intFromPtr(exe.udp_train) - exe.base_address),
        .udp_decode = @truncate(@intFromPtr(exe.udp_decode) - exe.base_address),
        .udp_encode = @truncate(@intFromPtr(exe.udp_encode) - exe.base_address),
        .alloca_probe = @truncate(@intFromPtr(exe.alloca_probe) - exe.base_address),
    };

    const dir = std.fs.path.dirname(path) orelse ".";
    // Idempotent and makes any intermediary dirs too, harmless to repeat
    try std.fs.cwd().makePath(dir);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = std.mem.asBytes(&entry) });
}

fn resolvePath(override: ?[]const u8, hash: u64, buf: []u8) ![]const u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sig_buf: [11]u8 = undefined;
    const dir = resolveCacheDir(override, &dir_buf);
    return std.fmt.bufPrint(buf, "{s}/ffxiv.sig.{s}.{s}.dat", .{ dir, CACHE_VERSION, b62.encode(hash, &sig_buf) });
}

fn resolveCacheDir(override: ?[]const u8, buf: []u8) []const u8 {
    if (override) |o| {
        if (std.mem.indexOfScalar(u8, o, 0)) |null_pos| return o[0..null_pos];
        return o;
    }

    if (std.posix.getenv("XDG_CACHE_HOME")) |xdg|
        return std.fmt.bufPrint(buf, "{s}/daigoro", .{xdg}) catch ".";

    if (std.posix.getenv("HOME")) |home|
        return std.fmt.bufPrint(buf, "{s}/.cache/daigoro", .{home}) catch ".";

    return ".";
}

test "Cache field offsets stable for on-disk format" {
    // These offsets define the .dat file format. Changing any offset silently breaks existing cache files.
    try std.testing.expectEqual(0, @offsetOf(CacheEntry, "hash"));
    try std.testing.expectEqual(8, @offsetOf(CacheEntry, "htbits"));
    try std.testing.expectEqual(12, @offsetOf(CacheEntry, "window"));
    try std.testing.expectEqual(16, @offsetOf(CacheEntry, "shared_size"));
    try std.testing.expectEqual(20, @offsetOf(CacheEntry, "set_malloc_free"));
    try std.testing.expectEqual(24, @offsetOf(CacheEntry, "shared_set_win"));
    try std.testing.expectEqual(28, @offsetOf(CacheEntry, "udp_state_size"));
    try std.testing.expectEqual(32, @offsetOf(CacheEntry, "udp_train"));
    try std.testing.expectEqual(36, @offsetOf(CacheEntry, "udp_decode"));
    try std.testing.expectEqual(40, @offsetOf(CacheEntry, "udp_encode"));
    try std.testing.expectEqual(44, @offsetOf(CacheEntry, "alloca_probe"));
}

test "Cache survives serialise/deserialise round-trip" {
    const original = CacheEntry{
        .hash = 0xDEADBEEF_CAFEBABE,
        .htbits = 17,
        .window = 0x100000,
        .shared_size = 0xABCD,
        .set_malloc_free = 0x1234,
        .shared_set_win = 0x5678,
        .udp_state_size = 0x9ABC,
        .udp_train = 0xDEF0,
        .udp_decode = 0x1111,
        .udp_encode = 0x2222,
        .alloca_probe = 0x3333,
    };

    // Simulate the save path: raw bytes as written to disk
    const bytes = std.mem.asBytes(&original);
    try std.testing.expectEqual(@as(usize, 48), bytes.len);

    // Simulate the load path: reinterpret bytes read from disk
    const loaded: *const CacheEntry = @ptrCast(@alignCast(bytes.ptr));
    try std.testing.expectEqual(original.hash, loaded.hash);
    try std.testing.expectEqual(original.htbits, loaded.htbits);
    try std.testing.expectEqual(original.window, loaded.window);
    try std.testing.expectEqual(original.shared_size, loaded.shared_size);
    try std.testing.expectEqual(original.set_malloc_free, loaded.set_malloc_free);
    try std.testing.expectEqual(original.shared_set_win, loaded.shared_set_win);
    try std.testing.expectEqual(original.udp_state_size, loaded.udp_state_size);
    try std.testing.expectEqual(original.udp_train, loaded.udp_train);
    try std.testing.expectEqual(original.udp_decode, loaded.udp_decode);
    try std.testing.expectEqual(original.udp_encode, loaded.udp_encode);
    try std.testing.expectEqual(original.alloca_probe, loaded.alloca_probe);
}

test "Cache survives file save/load round-trip" {
    // Save a synthetic signature set, reload it, verify fields match.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &abs_buf);

    const original = CacheEntry{
        .hash = 0xDEADBEEF_CAFEBABE,
        .htbits = 17,
        .window = 0x100000,
        .shared_size = 0xABCD,
        .set_malloc_free = 0x1234,
        .shared_set_win = 0x5678,
        .udp_state_size = 0x9ABC,
        .udp_train = 0xDEF0,
        .udp_decode = 0x1111,
        .udp_encode = 0x2222,
        .alloca_probe = 0x3333,
    };

    // Build a synthetic signature set whose RVAs match our CacheEntry above.
    const base = 0x140000;
    const exe = ffxiv{
        .htbits = original.htbits,
        .window = original.window,
        .base_address = base,
        .shared_size = @ptrFromInt(base + original.shared_size),
        .set_malloc_free = @ptrFromInt(base + original.set_malloc_free),
        .shared_set_win = @ptrFromInt(base + original.shared_set_win),
        .udp_state_size = @ptrFromInt(base + original.udp_state_size),
        .udp_train = @ptrFromInt(base + original.udp_train),
        .udp_decode = @ptrFromInt(base + original.udp_decode),
        .udp_encode = @ptrFromInt(base + original.udp_encode),
        .alloca_probe = @ptrFromInt(base + original.alloca_probe),
    };

    try save(dir, original.hash, exe);
    const loaded = load(dir, 0xDEADBEEF_CAFEBABE).?;

    try std.testing.expectEqual(original.htbits, loaded.htbits);
    try std.testing.expectEqual(original.window, loaded.window);
    try std.testing.expectEqual(original.shared_size, loaded.shared_size);
    try std.testing.expectEqual(original.set_malloc_free, loaded.set_malloc_free);
    try std.testing.expectEqual(original.udp_state_size, loaded.udp_state_size);
    try std.testing.expectEqual(original.udp_train, loaded.udp_train);
    try std.testing.expectEqual(original.udp_decode, loaded.udp_decode);
    try std.testing.expectEqual(original.udp_encode, loaded.udp_encode);
    try std.testing.expectEqual(original.alloca_probe, loaded.alloca_probe);
}

test "Cache miss on hash mismatch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &abs_buf);

    const entry = CacheEntry{
        .hash = 0xBEEF_BABE,
        .htbits = 0,
        .window = 0,
        .shared_size = 0,
        .set_malloc_free = 0,
        .shared_set_win = 0,
        .udp_state_size = 0,
        .udp_train = 0,
        .udp_decode = 0,
        .udp_encode = 0,
        .alloca_probe = 0,
    };
    // save needs an ffxiv value, so build one with matching RVAs
    const base: usize = 0x1000;
    const exe = ffxiv{
        .htbits = 0,
        .window = 0,
        .base_address = base,
        .shared_size = @ptrFromInt(base),
        .set_malloc_free = @ptrFromInt(base),
        .shared_set_win = @ptrFromInt(base),
        .udp_state_size = @ptrFromInt(base),
        .udp_train = @ptrFromInt(base),
        .udp_decode = @ptrFromInt(base),
        .udp_encode = @ptrFromInt(base),
        .alloca_probe = @ptrFromInt(base),
    };

    try save(dir, entry.hash, exe);
    // Load with a different hash, should miss
    const loaded = load(dir, 0xA11A0_A11A0);
    try std.testing.expectEqual(@as(?CacheEntry, null), loaded);
}

test "Cache miss on missing file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &abs_buf);

    // tmpdir is empty, so load returns null
    const loaded = load(dir, 0xDEADBEEF_CAFEBABE);
    try std.testing.expectEqual(@as(?CacheEntry, null), loaded);
}
