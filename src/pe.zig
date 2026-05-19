const std = @import("std");
const win32 = @import("win32.zig");
const internal = @import("log.zig");
const ImageError = @import("errors.zig").ImageError;

pub const PeImage = struct {
    // The slice covers the full mapped image from the first byte of the headers to SizeOfImage.
    // All RVAs in the PE structures are offsets into this slice.
    gpa: std.mem.Allocator,
    data: []align(std.heap.page_size_min) u8,
    data_size: usize,
    sections: []const win32.ImageSectionHeader,

    // Metadata for the domain-specific logic to use
    hash: u64,
    original: u64,
    reloc_va: u32,
    reloc_size: u32,

    pub fn load(exe_path: []const u8, allocator: std.mem.Allocator) ImageError!PeImage {
        const exe = std.fs.cwd().openFile(exe_path, .{}) catch |err| {
            return switch (err) {
                error.FileNotFound => error.FileNotFound,
                else => error.FileNotRead,
            };
        };
        defer exe.close();
        const file_size = (exe.stat() catch return error.FileNotRead).size;

        const raw_file = std.posix.mmap(null, file_size, std.posix.PROT.READ, .{ .TYPE = .SHARED }, exe.handle, 0) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.AllocationFailed,
                else => error.FileNotRead,
            };
        };
        errdefer std.posix.munmap(raw_file);

        // Validate DOS header magic ("MZ") before dereferencing anything else.
        if (raw_file.len < @sizeOf(win32.ImageDosHeader)) return error.FileTooSmall;
        const dos = @as(*const win32.ImageDosHeader, @ptrCast(@alignCast(raw_file[0..@sizeOf(win32.ImageDosHeader)].ptr)));
        if (dos.e_magic != win32.IMAGE_DOS_SIGNATURE) return error.InvalidDosHeader;

        // The NT headers start at e_lfanew. Validate PE signature ("PE\0\0").
        const nth_offset = dos.e_lfanew;
        const nth_end = nth_offset + @sizeOf(win32.ImageNtHeaders64);
        if (raw_file.len < nth_end) return error.InvalidNtHeaderOffset;

        const nth = @as(*const win32.ImageNtHeaders64, @ptrCast(@alignCast(raw_file[nth_offset..nth_end].ptr)));
        if (nth.signature != win32.IMAGE_NT_SIGNATURE) return error.InvalidNtHeader;
        if (nth.optional_header.magic != win32.IMAGE_OPTIONAL_SIGNATURE) return error.UnknownArch;

        // DataDirectory index 5 is Base Relocation
        const reloc_dir = nth.optional_header.data_directory[5];

        // Allocate the virtual image. mmap returns memory aligned to page size.
        // We request PROT_READ | PROT_WRITE initially so we can populate it;
        // mprotect will add PROT_EXEC and remove PROT_WRITE after relocation.
        const image_size = nth.optional_header.size_of_image;
        const image = std.posix.mmap(
            @ptrFromInt(nth.optional_header.image_base),
            image_size,
            std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true },
            -1,
            0,
        ) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.AllocationFailed,
                else => error.FileNotRead,
            };
        };
        errdefer std.posix.munmap(image);

        // Map each section from its file offset to its virtual address.
        // Sections may be smaller on disk than in memory (e.g. BSS); the
        // remainder stays zeroed from the mmap.
        const sections_count = nth.file_header.number_of_sections;
        const sections_offset = nth_end;
        const sections_end = sections_offset + (sections_count * @sizeOf(win32.ImageSectionHeader));
        if (raw_file.len < sections_end) return error.SectionTableOutOfBounds;

        const sections_raw = std.mem.bytesAsSlice(win32.ImageSectionHeader, raw_file[sections_offset..sections_end]);
        for (sections_raw) |sec| {
            const src_end = sec.pointer_to_raw_data + sec.size_of_raw_data;
            if (src_end > raw_file.len) return error.SectionDataOutOfBounds;

            const src = raw_file[sec.pointer_to_raw_data..src_end];
            const dst_len = @min(sec.size_of_raw_data, sec.virtual_size);
            if (sec.virtual_address + dst_len > image.len) return error.SectionVirtualOutOfBounds;

            @memcpy(image[sec.virtual_address..][0..dst_len], src[0..dst_len]);
        }
        const sections_raw_aligned = @as([]const win32.ImageSectionHeader, @alignCast(sections_raw));
        const sections_persist = allocator.dupe(win32.ImageSectionHeader, sections_raw_aligned) catch return error.AllocationFailed;

        return .{
            .data = image,
            .data_size = image_size,
            .hash = file_hash,
            .original = nth.optional_header.image_base,
            .reloc_va = reloc_dir.virtual_address,
            .reloc_size = reloc_dir.size,
            .sections = sections_persist,
            .gpa = allocator,
        };
    }

    // Switch the mapping to read+execute. From this point forward, the image memory cannot be written to.
    // Any attempt to do so will fault. The NOP/RET patches must be applied BEFORE this call.
    pub fn protect(self: *PeImage) ImageError!void {
        // Protect the Headers (usually the first page)
        // We set this to READ-only to prevent accidental corruption of the PE metadata.
        const header = if (self.sections.len > 0) self.sections[0].virtual_address else self.data.len;
        if (header > 0) {
            const protect_len = std.mem.alignForward(usize, header, std.heap.page_size_min);
            const protect_slice = self.data[0..@min(protect_len, self.data.len)];
            std.posix.mprotect(@alignCast(protect_slice), std.posix.PROT.READ) catch return error.ProtectFailed;
        }

        // Protect each section based on its flags
        for (self.sections) |sec| {
            if (sec.virtual_size == 0) continue;

            var prot: u32 = std.posix.PROT.NONE;
            // Using standard PE characteristic flag bits
            if (sec.flags.MEM_READ != 0) prot |= std.posix.PROT.READ;
            if (sec.flags.MEM_WRITE != 0) prot |= std.posix.PROT.WRITE;
            if (sec.flags.MEM_EXECUTE != 0) prot |= std.posix.PROT.EXEC;

            // Determine the slice for this section
            // We use VirtualSize but the OS will protect the entire page(s)
            const section_slice = self.data[sec.virtual_address..][0..sec.virtual_size];
            std.posix.mprotect(@alignCast(section_slice), prot) catch |err| {
                internal.debug("mprotect failed for section at 0x{x}: {any}\n", .{ sec.virtual_address, err });
                return error.ProtectFailed;
            };
        }
    }

    pub fn section(self: *const PeImage, name: []const u8) ?[]const u8 {
        for (self.sections) |*s| {
            const section_name = s.getName() orelse "";
            if (std.mem.eql(u8, section_name, name))
                return self.data[s.virtual_address..][0..s.virtual_size];
        }
        return null;
    }

    pub fn deinit(self: *PeImage) void {
        self.gpa.free(self.sections);
        std.posix.munmap(self.data[0..self.data_size]);
        self.* = undefined;
    }

    pub fn applyRelocations(self: *PeImage) ImageError!void {
        if (self.reloc_size == 0) return; // Some images have no relocations

        const base_addr = @intFromPtr(self.data.ptr);
        // The delta is how much every embedded absolute address needs to change.
        // For 64-bit arithmetic we work with i64 to handle the sign correctly.
        const delta: i64 = @as(i64, @intCast(base_addr)) -% @as(i64, @intCast(self.original));
        if (delta == 0) return;

        var offset = self.reloc_va;
        const end = offset + self.reloc_size;

        while (offset < end) {
            const block = std.mem.bytesAsValue(
                win32.ImageRelocationBase,
                self.data[offset..][0..@sizeOf(win32.ImageRelocationBase)],
            );

            if (block.block_size < @sizeOf(win32.ImageRelocationBase)) return error.RelocationOutOfBounds;

            const entries_start = offset + @sizeOf(win32.ImageRelocationBase);
            const entries_count = (block.block_size - @sizeOf(win32.ImageRelocationBase)) / 2;
            const entries = std.mem.bytesAsSlice(
                u16,
                self.data[entries_start..][0 .. entries_count * 2],
            );

            for (entries) |entry| {
                const reloc: win32.ImageRelocationEntry = @bitCast(entry);
                const target_rva = block.page_rva + @as(u32, @intCast(reloc.offset));

                if (target_rva + 8 > self.data.len) return error.RelocationOutOfBounds;

                switch (reloc.type) {
                    .ABSOLUTE => {}, // IMAGE_REL_BASED_ABSOLUTE: padding, ignore
                    .HIGHLOW => {
                        // IMAGE_REL_BASED_HIGHLOW: 32-bit absolute address.
                        // Add the low 32 bits of the delta.
                        // Used in 32-bit code and in some 64-bit PE files for data references.
                        const ptr = @as(*u32, @ptrCast(@alignCast(&self.data[target_rva])));
                        ptr.* +%= @truncate(@as(u64, @bitCast(delta)));
                    },
                    .DIR64 => {
                        // IMAGE_REL_BASED_DIR64: 64-bit absolute address.
                        // This is the common type for 64-bit code.
                        const ptr = @as(*u64, @ptrCast(@alignCast(&self.data[target_rva])));
                        ptr.* +%= @as(u64, @bitCast(delta));
                    },
                    else => return error.UnknownRelocationType,
                }
            }

            offset += block.block_size;
        }
    }

    pub fn rvaPtr(self: PeImage, rva: u32) *anyopaque {
        return @ptrFromInt(@intFromPtr(self.data.ptr) + rva);
    }
};

test "PE struct sizes match specification" {
    // These duplicate the comptime assertions so that `zig build test` reports them as test results rather than
    // compile errors, making it easier to diagnose which struct is wrong if a change breaks layout.
    try std.testing.expectEqual(64, @sizeOf(win32.ImageDosHeader));
    try std.testing.expectEqual(20, @sizeOf(win32.ImageFileHeader));
    try std.testing.expectEqual(240, @sizeOf(win32.ImageOptionalHeader64));
    try std.testing.expectEqual(8, @sizeOf(win32.ImageDataDirectory));
    try std.testing.expectEqual(40, @sizeOf(win32.ImageSectionHeader));

    // Generated field width checks: validate the reified type didn't accidentally widen or narrow critical fields.
    // Extract sizes at comptime from comptime-only @typeInfo, then validate at runtime to avoid cryptic errors.
    inline for (.{
        .{ .name = "image_base", .expected = @as(usize, 8) },
        .{ .name = "size_of_image", .expected = @as(usize, 4) },
        .{ .name = "size_of_stack_reserve", .expected = @as(usize, 8) },
        .{ .name = "data_directory", .expected = @as(usize, 128) },
    }) |check| {
        const actual = comptime blk: {
            const info = @typeInfo(win32.ImageOptionalHeader64).@"struct";
            var found: usize = 0;
            for (info.fields) |field| {
                if (std.mem.eql(u8, field.name, check.name)) {
                    found = @sizeOf(field.type);
                }
            }
            break :blk found;
        };
        if (actual == 0) {
            std.debug.print("\nFAIL: ImageOptionalHeader64 missing field '{s}'\n", .{check.name});
            return error.TestFailed;
        }
        try std.testing.expectEqual(check.expected, actual);
    }
}

test "PE struct field offsets match specification" {
    // ImageDosHeader - only the two fields we actually dereference
    try std.testing.expectEqual(0, @offsetOf(win32.ImageDosHeader, "e_magic"));
    try std.testing.expectEqual(60, @offsetOf(win32.ImageDosHeader, "e_lfanew"));

    // ImageFileHeader - the two fields used during PE loading
    try std.testing.expectEqual(2, @offsetOf(win32.ImageFileHeader, "number_of_sections"));
    try std.testing.expectEqual(16, @offsetOf(win32.ImageFileHeader, "size_of_optional_header"));

    // ImageDataDirectory - both fields accessed in load()
    try std.testing.expectEqual(0, @offsetOf(win32.ImageDataDirectory, "virtual_address"));
    try std.testing.expectEqual(4, @offsetOf(win32.ImageDataDirectory, "size"));

    // ImageSectionHeader - fields accessed in load() and protect()
    try std.testing.expectEqual(8, @offsetOf(win32.ImageSectionHeader, "virtual_size"));
    try std.testing.expectEqual(12, @offsetOf(win32.ImageSectionHeader, "virtual_address"));
    try std.testing.expectEqual(16, @offsetOf(win32.ImageSectionHeader, "size_of_raw_data"));
    try std.testing.expectEqual(20, @offsetOf(win32.ImageSectionHeader, "pointer_to_raw_data"));

    // ImageRelocationBase - both fields accessed in applyRelocations()
    try std.testing.expectEqual(0, @offsetOf(win32.ImageRelocationBase, "page_rva"));
    try std.testing.expectEqual(4, @offsetOf(win32.ImageRelocationBase, "block_size"));

    // ImageNtHeaders64 - the three embedded structs
    try std.testing.expectEqual(0, @offsetOf(win32.ImageNtHeaders64, "signature"));
    try std.testing.expectEqual(4, @offsetOf(win32.ImageNtHeaders64, "file_header"));
    try std.testing.expectEqual(24, @offsetOf(win32.ImageNtHeaders64, "optional_header"));

    // ImageOptionalHeader64 - the fields directly dereferenced in load()
    try std.testing.expectEqual(24, @offsetOf(win32.ImageOptionalHeader64, "image_base"));
    try std.testing.expectEqual(56, @offsetOf(win32.ImageOptionalHeader64, "size_of_image"));
    try std.testing.expectEqual(112, @offsetOf(win32.ImageOptionalHeader64, "data_directory"));

    // Verify data_directory[5] (base reloc) fits within the struct
    const reloc_dir_end = @offsetOf(win32.ImageOptionalHeader64, "data_directory") +
        5 * @sizeOf(win32.ImageDataDirectory) +
        @sizeOf(win32.ImageDataDirectory);
    try std.testing.expect(reloc_dir_end <= @sizeOf(win32.ImageOptionalHeader64));
}

test "PE constants match specification" {
    // These values are hard-coded in the PE spec. If they change, applyRelocations() will process the wrong relocation type or
    // hit the UnknownRelocationType error on valid PE files.
    try std.testing.expectEqual(0, @intFromEnum(win32.ImageRelocationType.ABSOLUTE));
    try std.testing.expectEqual(3, @intFromEnum(win32.ImageRelocationType.HIGHLOW));
    try std.testing.expectEqual(10, @intFromEnum(win32.ImageRelocationType.DIR64));

    // These bit values are hard-coded in the PE spec. If they change,  pe.protect() sets wrong mprotect flags,
    // potentially making code sections writable or data sections executable.
    const exec: win32.SectionHeaderFlags = .{ .MEM_EXECUTE = 1 };
    const read: win32.SectionHeaderFlags = .{ .MEM_READ = 1 };
    const write: win32.SectionHeaderFlags = .{ .MEM_WRITE = 1 };
    try std.testing.expectEqual(@as(u32, 0x20000000), @as(u32, @bitCast(exec)));
    try std.testing.expectEqual(@as(u32, 0x40000000), @as(u32, @bitCast(read)));
    try std.testing.expectEqual(@as(u32, 0x80000000), @as(u32, @bitCast(write)));
    try std.testing.expectEqual(32, @bitSizeOf(win32.SectionHeaderFlags));
}

test "relocation delta calculation" {
    // Construct a minimal PE image in memory, set up a known relocation, apply it, and verify the patched value.
    var fake_image align(std.heap.page_size_min) = [_]u8{0} ** 4096;
    // Write a known 64-bit address at some RVA.
    const original: u64 = 0x140000000; // Typical FFXIV ImageBase
    const embedded: u64 = original + 0x1234;
    const target_rva = 0x100;
    std.mem.writeInt(u64, fake_image[target_rva..][0..8], embedded, .little);

    // Bake a relocation table into the fake image.
    // We target the page starting at 0x0 so that page_rva (0) + offset (0x100) = target_rva.
    const reloc_va = 0x200;
    std.mem.writeInt(u32, fake_image[reloc_va + 0 ..][0..4], 0, .little); // page_rva
    std.mem.writeInt(u32, fake_image[reloc_va + 4 ..][0..4], 12, .little); // block_size (8 header + 2 entry + 2 padding)

    // Relocation Entry: DIR64 (10) at offset 0x100
    // (10 << 12) | 0x100 = 0xA100
    std.mem.writeInt(u16, fake_image[reloc_va + 8 ..][0..2], 0xA100, .little);

    // Apply relocation with a new base.
    var pe = PeImage{
        .gpa = std.testing.allocator,
        .data = fake_image[0..],
        .data_size = fake_image.len,
        .sections = &.{},
        .hash = 0,
        .original = original,
        .reloc_va = reloc_va,
        .reloc_size = 12,
    };

    try pe.applyRelocations();
    const new_base = @intFromPtr(pe.data.ptr);

    const result = std.mem.readInt(u64, fake_image[target_rva..][0..8], .little);
    const expected = new_base + 0x1234;

    // Get output in hex, easier to read what math failed
    if (result != expected) {
        std.debug.print("\nFAIL: Expected 0x{X}, found 0x{X}\n", .{ expected, result });
    }
    try std.testing.expectEqual(expected, result);
}
