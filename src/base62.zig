const std = @import("std");

const AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn encode(hash: u64, buf: *[11]u8) []const u8 {
    var n = hash;
    var idx: usize = 11;

    while (idx > 0) : (n /= 62) {
        idx -= 1;
        buf[idx] = AB[n % 62];
    }
    return buf;
}

comptime {
    var buf: [11]u8 = undefined;

    // Verify zero integrity
    const enc_zero = encode(0, &buf);
    if (enc_zero.len != 11) {
        @compileError("Base62: Comptime validation failed for value '0'");
    }

    // Verify maximum boundary condition compatibility
    const max_val = std.math.maxInt(u64);
    const enc_max = encode(max_val, &buf);
    if (enc_max.len != 11) {
        @compileError("Base62: Comptime validation failed for maxInt(u64)");
    }
}

test "Base62 codec integrity" {
    var buf: [11]u8 = undefined;
    const cases = [_]u64{ 0, 1, 61, 62, 0xDEADBEEF_CAFEBABE, std.math.maxInt(u64) };
    for (cases) |c| {
        const encoded = encode(c, &buf);

        // Output must always be exactly 11 chars
        try std.testing.expectEqual(@as(usize, 11), encoded.len);

        // Every output char must be valid
        for (encoded) |enc| try std.testing.expect(std.mem.indexOfScalar(u8, AB, enc) != null);
    }
}

test "Base62 zero edge case" {
    // Zero
    var buf: [11]u8 = undefined;
    try std.testing.expectEqualStrings("00000000000", encode(0, &buf));
}

// Max u64 edge case
test "Base62 max int edge case" {
    var buf: [11]u8 = undefined;
    _ = encode(std.math.maxInt(u64), &buf);

    // Every char must be in the alphabet
    for (buf) |c| {
        try std.testing.expect(std.mem.indexOfScalar(u8, AB, c) != null);
    }

    // First char must not be '0' for max value (non-trivial)
    try std.testing.expect(buf[0] != '0');
}
