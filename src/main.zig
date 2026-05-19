const std = @import("std");
const log = std.log.scoped(.oodle);

const daigoro = @import("daigoro").Context;

const PacketBuffer = struct {
    bytes: [1024 * 64]u8 = undefined, // 64KB static pool space
    read_idx: usize = 0,
    write_idx: usize = 0,

    inline fn remaining(self: PacketBuffer) usize {
        return self.write_idx;
    }

    inline fn writeableSlice(self: *PacketBuffer) []u8 {
        return self.bytes[self.write_idx..];
    }

    inline fn activeStream(self: PacketBuffer) []const u8 {
        return self.bytes[self.read_idx..self.write_idx];
    }

    inline fn compact(self: *PacketBuffer) void {
        if (self.read_idx > 0) {
            const len = self.remaining();
            std.mem.copyForwards(u8, self.bytes[0..len], self.bytes[self.read_idx..self.write_idx]);
            self.read_idx = 0;
            self.write_idx = len;
        }
    }
};

pub fn main() !void {
    // TODO: use a proper rundir path for this, symlink to /tmp on macos
    const socket_path = "/tmp/daigoro.sock";

    // Parse CLI args: oodle-helper <exe_path>
    var args = try std.process.argsWithAllocator(std.heap.page_allocator);
    defer args.deinit();
    const name = args.next() orelse unreachable;
    const exe_path = args.next() orelse {
        log.err("Usage: {s} <path/to/ffxiv_dx11.exe>\n", .{name});
        return error.MissingExePath;
    };

    // Lifecycle cleanup/setup
    std.posix.unlink(socket_path) catch {};
    const server = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(server);

    const address = try std.net.Address.initUnix(socket_path);
    try std.posix.bind(server, &address.any, address.getOsSockLen());

    // Initialise Daigoro
    var ctx = try daigoro.init(exe_path, null);
    defer ctx.deinit();

    // Start up the server
    try std.posix.listen(server, 10);
    log.info("Server started on {s}...\n", .{socket_path});

    // Listen to client connections
    while (true) {
        var client_addr: std.posix.sockaddr = undefined;
        var client_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const client_fd = std.posix.accept(server, &client_addr, &client_len, 0) catch |err| {
            log.err("Accept failed: {}\n", .{err});
            continue;
        };

        handleClient(client_fd, &ctx) catch |err| {
            log.err("Client disconnected with error: {}\n", .{err});
        };
    }
}

fn handleClient(fd: std.posix.fd_t, ctx: *daigoro) !void {
    defer std.posix.close(fd);

    const Header = extern struct {
        magic: u16, // 0x41FF -> "FF14" Little-Endian
        opcode: u8, // 0x01 = DecodeUDP, 0x02 = DecodeTCP, 0x03 = EncodeUDP, 0x04 = EncodeTCP
        source_len: u32, // Payload length sitting on the wire
        target_len: u32, // Safe memory constraint ceiling or expected decompression layout size
    };
    const HEADER_SIZE = @sizeOf(Header); // 11
    const SYNC_MAGIC: u16 = 0x41FF;

    var stream = PacketBuffer{};
    var work_buf: [1024 * 128]u8 = undefined;
    var write_buf: [1024 * 130]u8 = undefined;

    while (true) {
        stream.compact();

        const n = try std.posix.read(fd, stream.writeableSlice());
        if (n == 0) return; // Client safely closed the connection
        stream.write_idx += n;

        while (stream.remaining() >= HEADER_SIZE) {
            const current = stream.activeStream();
            const header: *align(1) const Header = @ptrCast(current[0..HEADER_SIZE]);

            if (header.magic != SYNC_MAGIC) return error.StreamOutOfSync;

            // Reject Out-of-Bounds opcodes
            if (header.opcode == 0 or header.opcode > 4) {
                log.err("Unknown opcode byte sequence: 0x{X:0>2}\n", .{header.opcode});
                return error.InvalidCommand;
            }

            // Reject TCP Modes
            // Decode TCP (0x02 / 0010) and Encode TCP (0x04 / 0100) both have a 0 in the lowest bit slot.
            if ((header.opcode & 0x01) == 0) {
                log.err("Unsupported TCP channel mode via command byte: 0x{X:0>2}\n", .{header.opcode});
                return error.UnsupportedChannelMode;
            }

            const total_packet_len = HEADER_SIZE + header.source_len;
            if (current.len < total_packet_len) break; // Complete body hasn't arrived over stream yet

            const payload = current[HEADER_SIZE..total_packet_len];

            var out_size: usize = 0;

            // Encode is used a lot less than decode, put it first so we can cold hint it out of the main path.
            // Decode UDP (0x01 / 0001) and Encode UDP (0x03 / 0011), switch on the second bit slot.
            if ((header.opcode & 0x02) != 0) {
                @branchHint(.cold);
                if (work_buf.len < header.target_len) {
                    log.err("Work buffer too small for encode: need {}, have {}\n", .{ header.target_len, work_buf.len });
                    return error.BufferTooSmall;
                }

                const res = try ctx.encode(payload.ptr, header.source_len, @ptrCast(&work_buf), header.target_len);
                out_size = @intCast(res);
            } else {
                if (work_buf.len < header.target_len) {
                    log.err("Work buffer too small for decode: need {}, have {}\n", .{ header.target_len, work_buf.len });
                    return error.BufferTooSmall;
                }

                try ctx.decode(payload.ptr, header.source_len, @ptrCast(&work_buf), header.target_len);
                out_size = header.target_len;
            }

            // Write response back over UDS
            std.mem.writeInt(u32, write_buf[0..4], @intCast(out_size), .little);
            std.mem.copyForwards(u8, write_buf[4 .. 4 + out_size], work_buf[0..out_size]);

            _ = try std.posix.write(fd, write_buf[0 .. 4 + out_size]);
            stream.read_idx += total_packet_len;
        }
    }
}
