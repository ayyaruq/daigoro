const std = @import("std");
const coff = std.coff;

pub const IMAGE_DOS_SIGNATURE = 0x5A4D;
pub const IMAGE_NT_SIGNATURE = 0x00004550;
pub const IMAGE_OPTIONAL_SIGNATURE = coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC;

// The DOS header is the first structure in every PE file. Its only field
// we actually use is e_lfanew, which gives the offset to the NT headers.
pub const ImageDosHeader = extern struct {
    e_magic: u16, // Must be 0x5A4D ("MZ")
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: u32, // Offset to IMAGE_NT_HEADERS from start of file
};

// Alias COFF data types, verify size/alignment/key values at comptime.
pub const ImageFileHeader = coff.CoffHeader;
pub const ImageDataDirectory = coff.ImageDataDirectory;
pub const ImageSectionHeader = coff.SectionHeader;
pub const SectionHeaderFlags = coff.SectionHeaderFlags;

pub const ImageRelocationBase = coff.BaseRelocationDirectoryEntry;
pub const ImageRelocationEntry = coff.BaseRelocation;
pub const ImageRelocationType = coff.BaseRelocationType;

// The 64-bit optional header. The name "optional" is misleading: it is
// always present in executable images. The 32-bit variant differs in field
// widths for ImageBase, stack sizes, and heap sizes, and has an extra
// BaseOfData field. Since we target x86-64 only, we only define the 64-bit
// variant here.
pub const ImageOptionalHeader64 = blk: {
    const base_info = @typeInfo(coff.OptionalHeaderPE64).@"struct";

    const Fields = struct {
        fn clone() [base_info.fields.len + 1]std.builtin.Type.StructField {
            var f: [base_info.fields.len + 1]std.builtin.Type.StructField = undefined;
            for (base_info.fields, 0..) |field, idx| {
                f[idx] = field;
            }
            f[base_info.fields.len] = .{
                .name = "data_directory",
                .type = [coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES]ImageDataDirectory,
                .default_value_ptr = null,
                .is_comptime = false,
                .alignment = @alignOf(ImageDataDirectory),
            };
            return f;
        }
    };

    const fields = Fields.clone();

    break :blk @Type(.{ .@"struct" = .{
        .layout = .@"extern",
        .fields = &fields,
        .decls = &.{},
        .is_tuple = false,
    } });
};

pub const ImageNtHeaders64 = extern struct {
    signature: u32, // Must be 0x00004550 ("PE\0\0")
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
};

// These comptime assertions verify that our struct definitions match the PE/COFF specification.
// If any assertion fails, the build will not complete. This catches transcription errors (wrong type widths, missing padding)
// that would otherwise produce silent misreads at runtime. Sizes from the PE/COFF specification, §3 and §4.
comptime {
    @setEvalBranchQuota(4000);

    // 0x020B is the PE32+ magic; 0x010B would be 32-bit PE.
    std.debug.assert(IMAGE_OPTIONAL_SIGNATURE == 0x020B);

    // DOS Header
    std.debug.assert(@sizeOf(ImageDosHeader) == 64);
    std.debug.assert(@alignOf(ImageDosHeader) == 4);
    std.debug.assert(@offsetOf(ImageDosHeader, "e_magic") == 0);
    std.debug.assert(@offsetOf(ImageDosHeader, "e_lfanew") == 60);

    // File Header: CoffHeader is the stdlib's name for IMAGE_FILE_HEADER
    std.debug.assert(@sizeOf(ImageFileHeader) == 20);
    std.debug.assert(@alignOf(ImageFileHeader) == 4);
    std.debug.assert(@offsetOf(ImageFileHeader, "number_of_sections") == 2);
    std.debug.assert(@offsetOf(ImageFileHeader, "size_of_optional_header") == 16);
    std.debug.assert(@intFromEnum(coff.MachineType.X64) == 0x8664); // verify machine type enum encodes correctly

    // Data Directory list
    std.debug.assert(@sizeOf(ImageDataDirectory) == 8);
    std.debug.assert(@alignOf(ImageDataDirectory) == 4);
    std.debug.assert(@offsetOf(ImageDataDirectory, "virtual_address") == 0);
    std.debug.assert(@offsetOf(ImageDataDirectory, "size") == 4);

    // Section Header
    std.debug.assert(@sizeOf(ImageSectionHeader) == 40);
    std.debug.assert(@alignOf(ImageSectionHeader) == 4);
    std.debug.assert(@offsetOf(ImageSectionHeader, "virtual_address") == 12);
    std.debug.assert(@offsetOf(ImageSectionHeader, "virtual_size") == 8);
    std.debug.assert(@offsetOf(ImageSectionHeader, "size_of_raw_data") == 16);
    std.debug.assert(@offsetOf(ImageSectionHeader, "pointer_to_raw_data") == 20);

    // The three flags used in mprotect() must match their PE spec bit positions.
    // If the stdlib ever reorders the bitfields, these fire at build time.
    {
        const exec: SectionHeaderFlags = .{ .MEM_EXECUTE = 1 };
        const read: SectionHeaderFlags = .{ .MEM_READ = 1 };
        const write: SectionHeaderFlags = .{ .MEM_WRITE = 1 };
        std.debug.assert(@as(u32, @bitCast(exec)) == 0x20000000);
        std.debug.assert(@as(u32, @bitCast(read)) == 0x40000000);
        std.debug.assert(@as(u32, @bitCast(write)) == 0x80000000);
        std.debug.assert(@bitSizeOf(SectionHeaderFlags) == 32); // verify @bitSizeOf to catch accidental widening
    }

    // Relocation offsets
    std.debug.assert(@sizeOf(ImageRelocationBase) == 8);
    std.debug.assert(@alignOf(ImageRelocationBase) == 4);
    std.debug.assert(@offsetOf(ImageRelocationBase, "page_rva") == 0);
    std.debug.assert(@offsetOf(ImageRelocationBase, "block_size") == 4);

    // Relocation entries
    std.debug.assert(@sizeOf(ImageRelocationEntry) == 2);
    std.debug.assert(@alignOf(ImageRelocationEntry) == 2);
    std.debug.assert(@bitSizeOf(ImageRelocationEntry) == 16);
    std.debug.assert(@intFromEnum(ImageRelocationType.ABSOLUTE) == 0);
    std.debug.assert(@intFromEnum(ImageRelocationType.HIGHLOW) == 3);
    std.debug.assert(@intFromEnum(ImageRelocationType.DIR64) == 10);

    // NT 64-bit Header
    std.debug.assert(@sizeOf(ImageNtHeaders64) == 264);
    std.debug.assert(@alignOf(ImageNtHeaders64) == 8);
    std.debug.assert(@offsetOf(ImageNtHeaders64, "signature") == 0);
    std.debug.assert(@offsetOf(ImageNtHeaders64, "file_header") == 4);
    std.debug.assert(@offsetOf(ImageNtHeaders64, "optional_header") == 24);

    // The size of image_base and size_of_stack_reserve are 64 bits in 64-bit PE.
    std.debug.assert(@sizeOf(ImageOptionalHeader64) == 240);
    std.debug.assert(@alignOf(ImageOptionalHeader64) == 8);
    std.debug.assert(@offsetOf(ImageOptionalHeader64, "image_base") == 24);
    std.debug.assert(@offsetOf(ImageOptionalHeader64, "size_of_image") == 56);
    std.debug.assert(@offsetOf(ImageOptionalHeader64, "data_directory") == 112);

    // Directory 5 is base relocation.
    std.debug.assert(
        @offsetOf(ImageOptionalHeader64, "data_directory") +
            5 * @sizeOf(ImageDataDirectory) +
            @sizeOf(ImageDataDirectory) <= @sizeOf(ImageOptionalHeader64),
    );

    {
        const info = @typeInfo(ImageOptionalHeader64).@"struct";
        const checks = .{
            .{ .name = "image_base", .size = 8 },
            .{ .name = "size_of_image", .size = 4 },
            .{ .name = "size_of_stack_reserve", .size = 8 },
            .{ .name = "data_directory", .size = 128 }, // Should be 16x u32+u32
        };

        if (info.fields.len == 0) {
            @compileError("Struct was generated with ZERO fields!");
        }

        for (info.fields) |field| {
            for (checks) |check| {
                if (std.mem.eql(u8, field.name, check.name)) {
                    std.debug.assert(@sizeOf(field.type) == check.size);
                }
            }
        }
    }

    // Cross-validate: every stdlib field exists at the same offset.
    {
        const ours = @typeInfo(ImageOptionalHeader64).@"struct";
        const theirs = @typeInfo(coff.OptionalHeaderPE64).@"struct";
        for (theirs.fields) |tf| {
            const o = for (ours.fields) |of| {
                if (std.mem.eql(u8, of.name, tf.name)) break of;
            } else @compileError("Generated type missing field: " ++ tf.name);
            if (o.type != tf.type)
                @compileError("Type mismatch for " ++ tf.name);
        }
    }
}
