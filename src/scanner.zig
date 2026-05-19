const std = @import("std");
const ScannerError = @import("errors.zig").ScannerError;

/// Private helper to parse a string pattern at compile-time.
fn parseStrPattern(comptime str: []const u8) []const ?u8 {
    comptime {
        var count: usize = 0;
        var i: usize = 0;
        while (i < str.len) {
            while (i < str.len and str[i] == ' ') : (i += 1) {}
            if (i >= str.len) break;
            count += 1;
            while (i < str.len and str[i] != ' ') : (i += 1) {}
        }

        var pattern: [count]?u8 = undefined;
        var idx: usize = 0;
        i = 0;
        while (i < str.len) {
            while (i < str.len and str[i] == ' ') : (i += 1) {}
            if (i >= str.len) break;
            const start = i;
            while (i < str.len and str[i] != ' ') : (i += 1) {}
            const token = str[start..i];

            if (std.mem.eql(u8, token, "??") or std.mem.eql(u8, token, "?")) {
                pattern[idx] = null;
            } else {
                pattern[idx] = std.fmt.parseInt(u8, token, 16) catch {
                    @compileError("Invalid hex byte: '" ++ token ++ "'");
                };
            }
            idx += 1;
        }
        const final = pattern;
        return &final;
    }
}

/// Private helper that inspects the input type at comptime.
/// - If it's a string, it parses it.
/// - If it's already an array/slice of optional bytes, it returns it directly.
fn ensurePattern(comptime input: anytype) []const ?u8 {
    const T = @TypeOf(input);
    return comptime blk: {
        switch (@typeInfo(T)) {
            .pointer => |ptr| {
                const child_info = @typeInfo(ptr.child);

                // Pointer to an Array (String literals or &.{...})
                if (child_info == .array) {
                    const arr = child_info.array;
                    // It's a string literal like "48 8B ?? E8"
                    if (arr.child == u8) break :blk parseStrPattern(input);

                    // It's a pointer to an array of ?u8, like &.{0x48, null}
                    if (arr.child == ?u8) {
                        const slice: []const ?u8 = input;
                        break :blk slice;
                    }
                }

                // Already a slice of ?u8, like &.{0x48, null}
                if (ptr.child == ?u8) break :blk input;

                // If it's a pointer but didn't match our criteria
                @compileError("Pointer to " ++ @typeName(ptr.child) ++ " is not a valid pattern source.");
            },

            // This unrolls for every other tag (int, float, struct, etc.)
            inline else => |info| {
                @compileError("Unsupported pattern type: " ++ @tagName(info) ++ " (" ++ @typeName(T) ++ "). Expected a string literal or an array/slice of ?u8.");
            },
        }
    };
}

// A capture region is a half-open byte range [start, start+len) within a
// matched region. All indices are relative to the start of the pattern.
pub const CaptureRegion = struct {
    start: usize,
    len: usize,
};

pub fn Pattern(comptime raw_input: []const ?u8, comptime captures: []const CaptureRegion) type {
    // Comptime validation runs at build time. These checks ensure that the
    // pattern definition is internally consistent before any scan attempt.
    comptime {
        if (raw_input.len == 0) @compileError("Pattern must not be empty");
        for (captures) |cap| {
            if (cap.start + cap.len > raw_input.len) {
                @compileError("Capture region extends beyond pattern bounds");
            }
            if (cap.len == 0) @compileError("Capture region must have non-zero length");
        }
    }

    return struct {
        const Self = @This();
        pub const parsed = ensurePattern(raw_input);

        pub fn scan(data: []const u8) ?usize {
            if (data.len < parsed.len) return null;
            const limit = data.len - parsed.len + 1;

            outer: for (0..limit) |idx| {
                for (parsed, 0..) |expected, off| {
                    if (expected) |byte| {
                        if (data[idx + off] != byte) continue :outer;
                    }
                }
                return idx;
            }
            return null;
        }

        // Locate pattern in a neighbourhood instead of global image space, turns needle in haystack to needle in pin cushion.
        // Retrieve capture directly from neighbourhood slice.
        pub fn captureLocal(neighbourhood: []const u8, comptime capture_idx: usize) ScannerError!i32 {
            const offset = Self.scan(neighbourhood) orelse return error.SigNotFound;
            const bytes = Self.getCapture(neighbourhood, offset, capture_idx);
            return std.mem.readInt(i32, bytes[0..4], .little);
        }

        pub fn resolveLocal(global: []const u8, neighbourhood: []const u8, start: usize, comptime capture_idx: usize) ScannerError!usize {
            const offset = Self.scan(neighbourhood) orelse return error.SigNotFound;
            return Self.resolveRelativeCall(global, start + offset, capture_idx);
        }

        pub fn verify(data: []const u8) bool {
            if (data.len < parsed.len) return false;

            for (parsed, 0..) |expected, idx| {
                // If expected is null (wildcard), we skip the check.
                if (expected) |byte| {
                    if (data[idx] != byte) return false;
                }
            }
            return true;
        }

        // Return the raw bytes of a capture region from a match, match_offset is the value returned by scan().
        pub fn getCapture(data: []const u8, match_offset: usize, comptime capture_idx: usize) []const u8 {
            const cap = captures[capture_idx];
            return data[match_offset + cap.start ..][0..cap.len];
        }

        // Interpret a 4-byte capture as a signed rel32 displacement and returns the absolute address it refers to.
        // This matches the x86-64 CALL rel32 encoding: the address is relative to the byte after the 4-byte operand.
        pub fn resolveRelativeCall(data: []const u8, match_offset: usize, comptime capture_idx: usize) usize {
            const cap = captures[capture_idx];
            comptime std.debug.assert(cap.len == 4);

            const cap_bytes = getCapture(data, match_offset, capture_idx);
            const rel32 = std.mem.readInt(i32, cap_bytes[0..4], .little);

            // RIP points to the *next* instruction right after the 4-byte displacement.
            // Use base ptr to apply math to ptr to avoid out of bounds indices.
            const next_rip = @intFromPtr(data.ptr) + match_offset + cap.start + 4;

            // Safely handle possible negative rel32 displacements.
            // The math is done safely using signed integers, but the final address is a standard pointer-sized uint.
            const target_addr = @as(isize, @intCast(next_rip)) + rel32;
            return @intCast(target_addr);
        }
    };
}

test "exact byte match" {
    const P = Pattern(
        &[_]?u8{ 0xE8, null, null, null, null },
        &[_]CaptureRegion{.{ .start = 1, .len = 4 }},
    );
    const data = [_]u8{ 0x00, 0x90, 0xE8, 0x01, 0x02, 0x03, 0x04, 0x00 };
    const offset = P.scan(&data);
    try std.testing.expectEqual(@as(?usize, 2), offset);
}

test "wildcard matches any byte" {
    const P = Pattern(
        &[_]?u8{ 0xAA, null, 0xBB },
        &[_]CaptureRegion{.{ .start = 1, .len = 1 }},
    );
    // The wildcard at index 1 should match 0xFF.
    const data = [_]u8{ 0xAA, 0xFF, 0xBB };
    try std.testing.expectEqual(@as(?usize, 0), P.scan(&data));
}

test "no match returns null" {
    const P = Pattern(
        &[_]?u8{ 0xAA, 0xBB },
        &[_]CaptureRegion{.{ .start = 0, .len = 1 }},
    );
    const data = [_]u8{ 0xAA, 0xCC };
    try std.testing.expectEqual(@as(?usize, null), P.scan(&data));
}

test "relative call resolution" {
    // E8 FC FF FF FF is CALL with rel32 = -4, which resolves to
    // (address of byte after the operand) + (-4) = address of the E8 itself.
    // This is a degenerate but well-defined case useful for testing the math.
    const P = Pattern(
        &[_]?u8{ 0xE8, null, null, null, null },
        &[_]CaptureRegion{.{ .start = 1, .len = 4 }},
    );
    var data = [_]u8{ 0xE8, 0xFB, 0xFF, 0xFF, 0xFF }; // rel32 = -5
    const offset = P.scan(&data).?;
    const resolved = P.resolveRelativeCall(&data, offset, 0);
    // -5 from end of operand (offset 5) = offset 0, which is &data[0].
    try std.testing.expectEqual(@intFromPtr(&data[0]), resolved);
}
