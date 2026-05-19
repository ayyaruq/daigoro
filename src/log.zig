const std = @import("std");
const builtin = @import("builtin");

const internal_logger = std.log.scoped(.internal);

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    if (builtin.mode == .Debug or builtin.is_test) {
        // Using internal_logger.err ensures it won't be filtered out by default test log levels
        internal_logger.err(fmt, args);
    }
}
