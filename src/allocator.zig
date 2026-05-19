const std = @import("std");
const Allocator = std.mem.Allocator;

// Global pointer to the active OodleAllocator. Set during init, cleared during destroy.
// The callback functions below use this pointer.
pub var g_oodle_alloc: ?*OodleAllocator = null;

// OodleAllocator wraps a GeneralPurposeAllocator and exposes the two function pointers that Oodle's SetMallocFree expects.
pub const OodleAllocator = struct {
    child_allocator: Allocator,

    // 64 bytes satisfies all modern SIMD (AVX-512) alignment requirements.
    const fixed_offset = 64;

    /// Per-allocation metadata stored immediately before the Oodle pointer.
    const Header = struct {
        size: usize,
        alignment: std.mem.Alignment,
    };

    pub fn allocator(self: *OodleAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
                .remap = remap,
            },
        };
    }

    pub fn init(child_allocator: Allocator) OodleAllocator {
        return .{ .child_allocator = child_allocator };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *OodleAllocator = @ptrCast(@alignCast(ctx));

        // Respect the requested SIMD alignment (e.g. 64) and ensure base alignment is at least our fixed_offset (64).
        const actual_align = std.mem.Alignment.fromByteUnits(@max(ptr_align.toByteUnits(), fixed_offset));
        const total_size = len + fixed_offset;

        const raw_mem = self.child_allocator.rawAlloc(total_size, actual_align, ret_addr) orelse return null;

        // Write Header at the start of the RAW allocation
        const header: *Header = @ptrCast(@alignCast(raw_mem));
        header.* = .{
            .size = total_size,
            .alignment = actual_align,
        };

        return @ptrFromInt(@intFromPtr(raw_mem) + fixed_offset);
    }

    /// Free a pointer previously returned by alloc(). Safe to call from both the Allocator vtable and
    /// the Win64 oodleFree callback.
    pub fn freePtr(self: *OodleAllocator, ptr: *anyopaque, ret_addr: usize) void {
        // Since Oodle only calls free on pointers we gave it, we know the Header is at (ptr - offset).
        const raw_addr = @intFromPtr(ptr) - fixed_offset;
        const header: *Header = @ptrFromInt(raw_addr);
        const full_slice = @as([*]u8, @ptrFromInt(raw_addr))[0..header.size];
        self.child_allocator.rawFree(full_slice, header.alignment, ret_addr);
    }

    // vtable free - just unwrap ctx and delegate
    fn free(ctx: *anyopaque, buf: []u8, _: std.mem.Alignment, ret_addr: usize) void {
        const self: *OodleAllocator = @ptrCast(@alignCast(ctx));

        // Safety: don't attempt math on null/empty slices
        if (@intFromPtr(buf.ptr) == 0) return;

        self.freePtr(buf.ptr, ret_addr);
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
};

// Callbacks passed to SetMallocFree. The PE code calls these directly when it needs to allocate or free memory internally.
// They access the active OodleAllocator via the module-level g_oodle_alloc pointer.
pub fn oodleMalloc(size: usize, align_val: i32) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    var state = g_oodle_alloc orelse return null;

    // Oodle usually passes 0 or 1 for "default", and power-of-two alignment otherwise.
    // Convert 16, 32, or 64 to Zig Alignment.
    const alignment = std.mem.Alignment.fromByteUnits(@intCast(@max(align_val, 1)));

    // OodleAllocator takes care of the SIMD padding and header storage.
    return @ptrCast(state.allocator().rawAlloc(size, alignment, @returnAddress()));
}

pub fn oodleFree(ptr: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    // Oodle's free does not pass the size or alignment.
    // The GPA tracks these internally via its allocation metadata, so we can recover them.
    const state = g_oodle_alloc orelse return;
    const raw_ptr = ptr orelse return;
    state.freePtr(raw_ptr, @returnAddress());
}

test "OodleAllocator returns aligned memory" {
    var opa = OodleAllocator.init(std.testing.allocator);
    g_oodle_alloc = &opa;
    defer g_oodle_alloc = null;

    // Allocate with 16-byte alignment and verify the returned pointer.
    const ptr = oodleMalloc(128, 16);
    try std.testing.expect(ptr != null);
    try std.testing.expectEqual(0, @intFromPtr(ptr.?) % 16);
    oodleFree(ptr.?);
}

test "OodleAllocator handles zero size" {
    var opa = OodleAllocator.init(std.testing.allocator);
    g_oodle_alloc = &opa;
    defer g_oodle_alloc = null;

    // Some allocators return null for zero-size requests. Verify our allocator does not crash either way.
    // No assertion - just verifying no crash or undefined behaviour.
    const ptr = oodleMalloc(0, 8);
    if (ptr) |p| oodleFree(p);
}

test "OodleAllocator SIMD alignment and leak check" {
    // This will catch leaks and invalid frees automatically
    var opa = OodleAllocator.init(std.testing.allocator);
    const alloc = opa.allocator();

    // Test various sizes and alignments
    const alignments = [_]usize{ 1, 2, 4, 8, 16, 32, 64 };

    for (alignments) |align_val| {
        const alignment = std.mem.Alignment.fromByteUnits(align_val);
        const size = 1024;

        const ptr = (alloc.rawAlloc(size, alignment, @returnAddress())) orelse return error.OutOfMemory;
        const slice = ptr[0..size];

        // Verify the pointer we got is actually 64-byte aligned (for SIMD)
        try std.testing.expect(@intFromPtr(slice.ptr) % 64 == 0);

        // Verify we can write to the start and end of the user memory
        slice[0] = 0xAA;
        slice[size - 1] = 0xBB;

        // Free it. If our math is wrong, std.testing.allocator will panic here.
        alloc.rawFree(slice, alignment, @returnAddress());
    }
}

test "OodleAllocator stress test" {
    var opa = OodleAllocator.init(std.testing.allocator);
    const alloc = opa.allocator();

    var list = std.ArrayList([]u8).init(std.testing.allocator);
    defer list.deinit();

    var prng = std.Random.DefaultPrng.init(0x1234);
    const random = prng.random();

    // Randomly allocate and free to check for fragmentation/header corruption
    for (0..1000) |_| {
        const size = random.intRangeAtMost(usize, 1, 1024 * 1024);
        const mem = try alloc.alloc(u8, size);
        try list.append(mem);

        if (list.items.len > 10) {
            const index = random.intRangeLessThan(usize, 0, list.items.len);
            const to_free = list.swapRemove(index);
            alloc.free(to_free);
        }
    }

    for (list.items) |mem| {
        alloc.free(mem);
    }
}
