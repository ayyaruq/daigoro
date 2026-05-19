const std = @import("std");
const ffxiv = @import("ffxiv.zig");
const OodleError = @import("errors.zig").OodleError;

xiv: ffxiv,
state: []u8, // udp state buffer, size = exe.udp_state_size()
shared: []u8, // shared hash table, size = exe.shared_size(exe.htbits)
window: []u8, // sliding window, size = exe.window
allocator: std.mem.Allocator,

const Self = @This();

pub fn init(exe: ffxiv, alloc: std.mem.Allocator) OodleError!Self {
    const state_len = exe.udp_state_size();
    const state_buf = alloc.alloc(u8, @intCast(state_len)) catch return error.AllocationFailed;
    errdefer alloc.free(state_buf);
    @memset(state_buf, 0);

    const shared_len = exe.shared_size(exe.htbits);
    const shared_buf = alloc.alloc(u8, @intCast(shared_len)) catch return error.AllocationFailed;
    errdefer alloc.free(shared_buf);
    @memset(shared_buf, 0);

    const window_buf = alloc.alloc(u8, @intCast(exe.window)) catch return error.AllocationFailed;
    errdefer alloc.free(window_buf);
    @memset(window_buf, 0);

    exe.shared_set_win(shared_buf.ptr, exe.htbits, window_buf.ptr, @intCast(window_buf.len));

    // Train with zeroed packets to initialise the state to a clean baseline.
    exe.udp_train(state_buf.ptr, shared_buf.ptr, null, null, 0);

    return .{ .xiv = exe, .state = state_buf, .shared = shared_buf, .window = window_buf, .allocator = alloc };
}

pub fn deinit(self: *Self) void {
    self.* = undefined;
}
