const std = @import("std");
const OodleError = @import("errors.zig").OodleError;

// Re-export for consumers
pub const Context = @import("context.zig").Context;

/// Module-level state for the C API. Zig consumers should use `context.zig` directly.
var g_ctx: ?Context = null;

/// Status codes returned by every fallible function. Callers should switch on the status rather than testing for `.ok` alone,
/// since the set of error codes may grow between library versions.
///
/// Values 1–8 are initialisation errors (only possible from `oodle_init`).
/// Values 11–12 are runtime errors (only possible from `oodle_decode` / `oodle_encode`).
const OodleStatus = enum(c_int) {
    ok = 0,
    err_file_not_found = 1, // exe_path does not exist
    err_file_read = 2, // file exists but could not be read fully
    err_not_pe = 3, // DOS magic or PE signature not found
    err_wrong_arch = 4, // PE is not x86-64 (PE32+ magic 0x20B)
    err_alloc = 5, // mmap or allocator failure
    err_reloc = 6, // relocation table contains unknown type
    err_sig_not_found = 7, // one or more byte patterns found no match
    err_patch_guard = 8, // NOP target bytes did not match expected
    err_not_init = 9, // oodle_init not called yet
    err_already_init = 10, // oodle_init called more than once
    err_decode_failed = 11, // Oodle returned false from decode
    err_encode_failed = 12, // Oodle returned ≤ 0 from encode, or dst_len too small

    comptime {
        const count = @typeInfo(OodleStatus).@"enum".fields.len;
        if (count != 13) {
            @compileError(std.fmt.comptimePrint("OodleStatus has {d} variants (was 13): update oodleStatusFromError().", count));
        }
    }
};

/// Bundles a status with the number of bytes written to the output buffer.
/// `bytes_written` is only meaningful when `status == .ok`.
const OodleResult = extern struct {
    status: OodleStatus,
    bytes_written: u32,

    comptime {
        if (@sizeOf(OodleResult) != 8) {
            @compileError("OodleResult size changed from 8: FFI reads offset at 0 and size at 4.");
        }

        if (@alignOf(OodleResult) != 4) {
            @compileError("OodleResult alignment changed from 4: FFI struct layout depends on this.");
        }

        if (@offsetOf(OodleResult, "status") != 0) {
            @compileError("OodleResult.status offset changed from 0: FFI expects status as the first field.");
        }

        if (@offsetOf(OodleResult, "bytes_written") != 4) {
            @compileError("OodleResult.bytes_written offset changed from 4: FFI expects this immediately after status.");
        }
    }
};

fn oodleStatusFromError(err: OodleError) OodleStatus {
    return switch (err) {
        error.AlreadyInitialised => OodleStatus.err_already_init,
        error.AllocationFailed => OodleStatus.err_alloc,
        error.DecodeFailed => OodleStatus.err_decode_failed,
        error.EncodeFailed => OodleStatus.err_encode_failed,
        error.FileNotFound => OodleStatus.err_file_not_found,
        error.FileNotRead => OodleStatus.err_file_read,
        error.PatchGuard => OodleStatus.err_patch_guard,
        error.SigNotFound => OodleStatus.err_sig_not_found,
        error.UnknownArch => OodleStatus.err_wrong_arch,
        error.UnknownImageType => OodleStatus.err_not_pe,
        error.UnknownRelocationType => OodleStatus.err_reloc,

        // ImageError coalesced into closest C-API status
        error.InvalidDosHeader, error.InvalidNtHeader, error.InvalidNtHeaderOffset, error.FileTooSmall => .err_not_pe,
        error.RelocationOutOfBounds, error.ProtectFailed, error.SectionDataOutOfBounds, error.SectionTableOutOfBounds, error.SectionVirtualOutOfBounds => .err_reloc,
        error.PatchOutOfBounds => OodleStatus.err_patch_guard,

        // ScannerError coalesced into closest C-API status
        error.InvalidCapture => .err_sig_not_found,
    };
}

/// Loads and prepares the Oodle functions from the game binary.
///
/// `exe_path` is a null-terminated UTF-8 path to ffxiv_dx11.exe. The pointer is not retained after the function returns.
///
/// `cache_dir` is an optional null-terminated UTF-8 path to a directory for signature cache files.
/// If null, the library resolves a default location:
///   1. $XDG_CACHE_HOME/daigoro     if XDG_CACHE_HOME is set
///   2. $HOME/.cache/daigoro        if HOME is set
///   3. ./                          current working directory (fallback)
///  The directory is created if it does not exist. Pass an explicit path to override.
///
/// Returns `.ok` on success, or an error status on failure. On failure the library remains uninitialised and may be retried.
/// On `.err_already_init` the existing state is not modified.
export fn oodle_init(exe_path: [*:0]const u8, cache_dir: ?[*:0]const u8) c_int {
    if (g_ctx != null) return @intFromEnum(OodleStatus.err_already_init);
    g_ctx = Context.init(
        std.mem.span(exe_path),
        if (cache_dir) |p| std.mem.span(p) else null,
    ) catch |err| return @intFromEnum(oodleStatusFromError(err));
    return @intFromEnum(OodleStatus.ok);
}

/// Releases all resources and resets the library to uninitialised. Safe to call when uninitialised (no-op).
/// After this call, `oodle_init` may be called again.
export fn oodle_destroy() void {
    if (g_ctx) |*ctx| {
        ctx.deinit();
        g_ctx = null;
    }
}

/// Returns the minimum output buffer size that `oodle_encode` requires for an input of the given length.
/// Currently `uncompressed_len + 8` per the Oodle contract, but callers should call this function rather than hardcoding the constant.
export fn oodle_max_compressed_size(n: u32) u32 {
    const ctx = &(g_ctx orelse return 0);
    return ctx.maxCompressedSize(n);
}

/// Decompresses a single compressed Zone frame payload.
///
/// `src` and `src_len` are the compressed input as received from the network, after stripping the FFXIV frame header.
///
/// `dst` and `dst_len` are the caller-allocated output buffer. `dst_len` MUST equal FFXIVARR_PACKET_HEADER.decompressedSize
/// from the frame header. Passing a wrong `dst_len` will produce garbled output or a decode failure.
///
/// `src` and `dst` must not overlap.
///
/// On `.err_decode_failed`, `dst` is zeroed to `dst_len` bytes and the Oodle state remains valid for subsequent calls.
/// The caller should log and discard the frame.
export fn oodle_decode(src: [*]const u8, src_len: u32, dst: [*]u8, dst_len: u32) OodleResult {
    const ctx = &(g_ctx orelse return .{ .status = .err_not_init, .bytes_written = 0 });

    ctx.decode(src, src_len, dst, dst_len) catch |err| {
        // The error is logged through oodle_last_error().
        ctx.setError("Oodle UDP decode failed: {s}", .{@errorName(err)});
        return .{ .status = oodleStatusFromError(err), .bytes_written = 0 };
    };

    return .{ .status = .ok, .bytes_written = dst_len };
}

/// Compresses `src` into `dst`.
///
/// `dst_len` must be at least `oodle_max_compressed_size(src_len)`. If it is not, `.err_encode_failed` is returned immediately without calling Oodle.
///
/// On success, `bytes_written` holds the actual compressed length, which will be less than or equal to `dst_len`.
/// The caller should use `bytes_written`, not `dst_len`, as the size of the compressed output.
///
/// Encode is provided primarily to support round-trip testing. It shares the same Oodle state as decode,
/// so encoding and decoding against the same instance should be consistent.
export fn oodle_encode(src: [*]const u8, src_len: u32, dst: [*]u8, dst_len: u32) OodleResult {
    const ctx = &(g_ctx orelse return .{ .status = .err_not_init, .bytes_written = 0 });

    const written = ctx.encode(src, src_len, dst, dst_len) catch |err| {
        ctx.setError("Oodle UDP encode failed", .{});
        return .{ .status = oodleStatusFromError(err), .bytes_written = 0 };
    };

    return .{ .status = .ok, .bytes_written = @intCast(written) };
}

/// Returns a human-readable description of the most recent error, or an empty string if no error has occurred.
/// The returned pointer is valid until the next call to any library function. The caller must not free it.
/// Use this for logging only; use `OodleStatus` for control flow.
export fn oodle_last_error() [*:0]const u8 {
    const ctx = &(g_ctx orelse return @ptrCast(&[_]u8{0} ** 512));
    return ctx.lastError();
}

test "Result API contract" {
    try std.testing.expectEqual(8, @sizeOf(OodleResult));
    try std.testing.expectEqual(4, @alignOf(OodleResult));
    try std.testing.expectEqual(0, @offsetOf(OodleResult, "status"));
    try std.testing.expectEqual(4, @offsetOf(OodleResult, "bytes_written"));
}

test "Status API contract" {
    const MappedError = struct {
        err: OodleError,
        expected: OodleStatus,
    };

    const mappings = [_]MappedError{
        .{ .err = OodleError.FileNotFound, .expected = .err_file_not_found },
        .{ .err = OodleError.FileNotRead, .expected = .err_file_read },
        .{ .err = OodleError.UnknownImageType, .expected = .err_not_pe },
        .{ .err = OodleError.UnknownArch, .expected = .err_wrong_arch },
        .{ .err = OodleError.AllocationFailed, .expected = .err_alloc },
        .{ .err = OodleError.UnknownRelocationType, .expected = .err_reloc },
        .{ .err = OodleError.SigNotFound, .expected = .err_sig_not_found },
        .{ .err = OodleError.PatchGuard, .expected = .err_patch_guard },
        .{ .err = OodleError.AlreadyInitialised, .expected = .err_already_init },
        .{ .err = OodleError.DecodeFailed, .expected = .err_decode_failed },
        .{ .err = OodleError.EncodeFailed, .expected = .err_encode_failed },
    };

    for (mappings) |m| {
        const actual = oodleStatusFromError(m.err);
        try std.testing.expectEqual(m.expected, actual);
        try std.testing.expect(@intFromEnum(oodleStatusFromError(m.err)) != @intFromEnum(OodleStatus.ok));
    }

    var seen: [mappings.len]OodleStatus = undefined;
    for (mappings, 0..) |m, idx| {
        seen[idx] = oodleStatusFromError(m.err);
    }

    for (seen, 0..) |a, idx| {
        for (seen[idx + 1 ..]) |b| {
            try std.testing.expect(a != b);
        }
    }

    // +2 for .ok and .err_not_init, comptime is because typeInfo isn't available at runtime
    try std.testing.expectEqual(mappings.len + 2, comptime @typeInfo(OodleStatus).@"enum".fields.len);
}
