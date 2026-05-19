//! FFXIV Oodle compression library for Zig consumers.
//!
//! Provides a single `Context` type that loads the Oodle functions from an FFXIV game executable and
//! exposes encode/decode for Zone packet payloads. The context owns all memory and must be
//! deinitialised when done.
//!
//! ```zig
//! const daigoro = @import("daigoro");
//!
//! var ctx = try daigoro.Context.init("ffxiv_dx11.exe", null);
//! defer ctx.deinit();
//!
//! const written = try ctx.encode(src.ptr, src.len, dst.ptr, dst.len);
//! try ctx.decode(dst.ptr, @intCast(written), out.ptr, src.len);
//! ```
//!
//! Only one context may be active at a time due to the PE callback mechanism. All methods are
//! single-threaded; the PE code is not thread-safe.

const std = @import("std");
const cache = @import("cache.zig");
const opa = @import("allocator.zig");
const pe = @import("pe.zig");
const ffxiv = @import("ffxiv.zig");
const Oodle = @import("oodle.zig");
const OodleError = @import("errors.zig").OodleError;

/// Active Context pointer for lifecycle management. The PE callbacks in allocator.zig read
/// opa.g_oodle_alloc to find the OodleAllocator; this pointer tracks the Context itself for
/// error reporting and init guards. Set by init, cleared by deinit.
var g_active: ?*Context = null;

/// Oodle compression context. Owns the mapped PE image, arena-allocated buffers, and the Oodle
/// engine state. Call `init` to create, `deinit` to release, and `encode`/`decode` for compression.
pub const Context = struct {
    state: State,
    /// Buffer for the most recent error message. Read via `lastError`.
    last_err: [512]u8 = .{0} ** 512,

    /// Loads the Oodle functions from an FFXIV game executable.
    ///
    /// `exe_path` is a filesystem path to ffxiv_dx11.exe. The file is mmap'd for the lifetime
    /// of the context.
    ///
    /// `cache_dir` is an optional directory for signature cache files. If null, resolves
    /// `$XDG_CACHE_HOME/daigoro`, `$HOME/.cache/daigoro`, or the current working directory.
    ///
    /// Returns `error.AlreadyInitialised` if a context is already active.
    /// Returns `error.FileNotFound` if the exe path doesn't exist.
    /// Returns `error.SigNotFound` if function signatures can't be located.
    pub fn init(exe_path: []const u8, cache_dir: ?[]const u8) OodleError!Context {
        if (g_active != null) return error.AlreadyInitialised;
        var self = Context{
            .state = try State.init(exe_path, cache_dir),
        };
        g_active = &self;
        return self;
    }

    /// Releases all resources: unmaps the PE image, frees arena memory, and clears the active
    /// context pointer. Safe to call multiple times; subsequent calls are no-ops.
    pub fn deinit(self: *Context) void {
        g_active = null;
        self.state.deinit();
        self.* = undefined;
    }

    /// Compresses `src_len` bytes from `src` into `dst`.
    ///
    /// `dst_len` must be at least `maxCompressedSize(src_len)`, otherwise `error.EncodeFailed`
    /// is returned without calling into Oodle.
    ///
    /// Returns the number of bytes written to `dst`, which will be ≤ `dst_len`. The caller should
    /// use the return value, not `dst_len`, as the compressed output size.
    ///
    /// `src` and `dst` must not overlap.
    pub fn encode(self: *Context, src: [*]const u8, src_len: u32, dst: [*]u8, dst_len: u32) OodleError!i32 {
        if (dst_len < self.maxCompressedSize(src_len)) return error.EncodeFailed;
        const result = self.state.engine.xiv.udp_encode(
            self.state.engine.state.ptr,
            self.state.engine.shared.ptr,
            src,
            src_len,
            dst,
        );
        if (result <= 0) return error.EncodeFailed;
        return @intCast(result);
    }

    /// Decompresses `src_len` bytes from `src` into `dst`.
    ///
    /// `dst_len` must equal the original uncompressed size from the FFXIV frame header. A wrong
    /// `dst_len` produces garbled output or a decode failure.
    ///
    /// On failure, `dst` is zeroed to `dst_len` bytes and the Oodle state remains valid for
    /// subsequent calls. The caller should log and discard the frame.
    pub fn decode(self: *Context, src: [*]const u8, src_len: u32, dst: [*]u8, dst_len: u32) OodleError!void {
        const ok = self.state.engine.xiv.udp_decode(
            self.state.engine.state.ptr,
            self.state.engine.shared.ptr,
            src,
            src_len,
            dst,
            dst_len,
        );
        if (!ok) {
            @memset(dst[0..dst_len], 0);
            return error.DecodeFailed;
        }
    }

    /// Returns the minimum output buffer size required by `encode` for an input of `n` bytes.
    /// Currently `n + 8` per the Oodle contract, but callers should use this function rather than
    /// hardcoding the constant.
    pub fn maxCompressedSize(_: *Context, n: u32) u32 {
        return n + 8;
    }

    /// Writes a formatted error message to the context's error buffer. Used internally by the
    /// C API wrappers; Zig consumers can call `lastError()` to retrieve the result.
    pub fn setError(self: *Context, comptime fmt: []const u8, args: anytype) void {
        _ = std.fmt.bufPrint(&self.last_err, fmt, args) catch {};
    }

    /// Returns a pointer to the most recent error message, or an empty string if no error has
    /// occurred. The pointer is valid until the next call to any Context method. The caller must
    /// not free it. Use this for logging only; use error return values for control flow.
    pub fn lastError(self: *Context) [*:0]const u8 {
        return @ptrCast(&self.last_err);
    }
};

// Internal PE state - image mapping, arena, Oodle engine.
const State = struct {
    image: pe.PeImage,
    arena: std.heap.ArenaAllocator,
    allocator: opa.OodleAllocator,
    engine: Oodle,

    fn init(exe_path: []const u8, cache_dir: ?[]const u8) OodleError!State {
        const gpa = std.heap.page_allocator;
        var image = try pe.PeImage.load(exe_path, cache_dir, gpa);
        errdefer image.deinit();

        const exe = if (ffxiv.fromCache(image)) |cached|
            cached
        else blk: {
            const scanned = try ffxiv.lookup(image);
            cache.save(cache_dir, image.hash, scanned) catch |err| {
                return switch (err) {
                    error.NoSpaceLeft => error.AllocationFailed,
                    else => error.FileNotRead,
                };
            };
            break :blk scanned;
        };

        // *MUST* patch before protect or cannot write to the memory.
        try exe.applyAllocaPatch(image.data);

        // Arena owns state/shared/window buffers - freed in one shot during deinit.
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();

        // OodleAllocator is allocated on the arena so the callback pointer is
        // stable for the lifetime of the library. No per-call rebinding needed.
        const alloc_ptr = arena.allocator().create(opa.OodleAllocator) catch return error.AllocationFailed;
        alloc_ptr.* = opa.OodleAllocator.init(gpa);
        opa.g_oodle_alloc = alloc_ptr;
        errdefer opa.g_oodle_alloc = null;

        // Bind malloc so Oodle can use it.
        exe.set_malloc_free(
            @ptrCast(@constCast(&opa.oodleMalloc)),
            @ptrCast(@constCast(&opa.oodleFree)),
        );

        var instance = try Oodle.init(exe, arena.allocator());
        errdefer instance.deinit();

        return .{ .image = image, .arena = arena, .allocator = alloc_ptr.*, .engine = instance };
    }

    fn deinit(self: *State) void {
        self.engine.deinit();
        opa.g_oodle_alloc = null;
        self.arena.deinit();
        self.image.deinit();
        self.* = undefined;
    }
};
