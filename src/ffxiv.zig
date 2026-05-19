const std = @import("std");
const pe = @import("pe.zig");
const sigs = @import("signature.zig");

const OodleError = @import("errors.zig").OodleError;

// All function pointers use the x86_64_win64 convention because they point into Windows-compiled code extracted from the PE image.
const FnSharedSize = fn (htbits: i32) callconv(.{ .x86_64_win = .{} }) i32;
const FnSharedSetWin = fn (data: *anyopaque, htbits: i32, window: *anyopaque, windowSize: i32) callconv(.{ .x86_64_win = .{} }) void;
const FnProtoTrain = fn (state: *anyopaque, shared: *anyopaque, packets: ?*const *const anyopaque, sizes: ?*const i32, count: i32) callconv(.{ .x86_64_win = .{} }) void;
const FnProtoStateSize = fn () callconv(.{ .x86_64_win = .{} }) i32;
const FnUdpDecode = fn (state: *const anyopaque, shared: *anyopaque, compressed: *const anyopaque, compressedSize: usize, raw: *anyopaque, rawSize: usize) callconv(.{ .x86_64_win = .{} }) bool;
const FnUdpEncode = fn (state: *const anyopaque, shared: *const anyopaque, raw: *const anyopaque, rawSize: usize, compressed: *anyopaque) callconv(.{ .x86_64_win = .{} }) i32;
const FnSetMallocFree = fn (pfnMalloc: *anyopaque, pfnFree: *anyopaque) callconv(.{ .x86_64_win = .{} }) void;

const Self = @This();

htbits: i32,
window: i32,
base_address: usize, // Address of the mapped image when scanned
shared_size: *FnSharedSize,
set_malloc_free: *FnSetMallocFree,
shared_set_win: *FnSharedSetWin,
udp_state_size: *FnProtoStateSize,
udp_train: *FnProtoTrain,
udp_decode: *FnUdpDecode,
udp_encode: *FnUdpEncode,
alloca_probe: *anyopaque, // We only overwrite this, no need for a "real" type

pub fn applyAllocaPatch(self: *const Self, image: []u8) OodleError!void {
    const patch = @intFromPtr(self.alloca_probe);
    const image_base = @intFromPtr(image.ptr);

    if (patch < image_base or patch + 1 > image_base + image.len) {
        return error.PatchOutOfBounds;
    }

    const rva = patch - image_base;
    const target = image[rva..];

    if (!sigs.PatternAlloca_x64.verify(target)) {
        return error.PatchGuard;
    }

    image[rva] = 0xC3; // RET - not NOP; kills the entire function on entry
}

pub fn fromCache(image: pe.PeImage) ?Self {
    const entry = image.data_cache orelse return null;

    var result: Self = undefined;
    result.htbits = entry.htbits;
    result.window = entry.window;
    result.base_address = @intFromPtr(image.data.ptr);

    inline for (std.meta.fields(Self)) |field| {
        // Skip the ones we handled manually above
        if (comptime std.mem.eql(u8, field.name, "base_address")) continue;
        if (comptime std.mem.eql(u8, field.name, "htbits")) continue;
        if (comptime std.mem.eql(u8, field.name, "window")) continue;

        // Map the RVA from the entry to a pointer in the result
        // This assumes field names match exactly (e.g. entry.udp_decode -> result.udp_decode)
        const rva = @field(entry, field.name);
        @field(result, field.name) = @ptrCast(image.rvaPtr(rva));
    }

    return result;
}

// Run the pattern scans to resolve all function pointers.
// The image slice must be the fully mapped, relocated PE image.
pub fn lookup(image: pe.PeImage) OodleError!Self {
    // All scans operate on the .text section slice, not the whole image.
    const text = image.section(".text") orelse return error.SigNotFound;

    // The Global CRT Probe (Independent of the Oodle block)
    const alloca_offset = sigs.PatternAlloca_x64.scan(image.data) orelse return error.SigNotFound;

    // SetMallocFree is immediately after oodle_init
    // Locate the Anchor (SetMallocFree) to find the neighborhood
    const anchor = sigs.PatternSetMallocFree.scan(text) orelse return error.SigNotFound;

    // Define the Neighbourhood Window (±0x5000 around Scan 1)
    const n_start = if (anchor > 0x20000) anchor - 0x5000 else 0;
    const n_end = @min(text.len, anchor + 0x20000);
    const hood = text[n_start..n_end];

    // Combined init pattern captures htbits, SharedSize, window, and SharedSetWindow in a single scan.
    // This avoids the false-positive problem that the standalone SharedSetWin pattern (42k matches) would have when scanned independently.
    const init_offset = sigs.PatternOodleInit.scan(hood) orelse return error.SigNotFound;

    return .{
        .base_address = @intFromPtr(image.data.ptr),

        .alloca_probe = image.rvaPtr(@intCast(alloca_offset)),
        .set_malloc_free = @ptrFromInt(sigs.PatternSetMallocFree.resolveRelativeCall(text, anchor, 0)),

        .htbits = std.mem.readInt(i32, sigs.PatternOodleInit.getCapture(hood, init_offset, 0)[0..4], .little),
        .shared_size = @ptrFromInt(sigs.PatternOodleInit.resolveRelativeCall(text, n_start + init_offset, 1)),
        .window = std.mem.readInt(i32, sigs.PatternOodleInit.getCapture(hood, init_offset, 2)[0..4], .little),
        .shared_set_win = @ptrFromInt(sigs.PatternOodleInit.resolveRelativeCall(text, n_start + init_offset, 3)),

        .udp_state_size = @ptrFromInt(try sigs.PatternStateSizes.resolveLocal(text, hood, n_start, 0)),
        .udp_train = @ptrFromInt(try sigs.PatternTrainPtrs.resolveLocal(text, hood, n_start, 1)),
        .udp_decode = @ptrFromInt(try sigs.PatternDecodePtrs.resolveLocal(text, hood, n_start, 1)),
        .udp_encode = @ptrFromInt(try sigs.PatternEncodePtrs.resolveLocal(text, hood, n_start, 1)),
    };
}
