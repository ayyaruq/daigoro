const std = @import("std");
const scanner = @import("scanner.zig");

// The 64-bit Oodle code contains an _alloca_probe call that crashes outside the original Windows process context.
// Overwriting its first byte with RET makes every call to it a no-op. The pattern identifies the function start
// reliably across patches.
pub const PatternAlloca_x64 = scanner.Pattern(
    &[_]?u8{
        0x48, 0x3D, 0x00, 0x10, 0x00, 0x00, // cmp rax, 1000h (page size check)
    },
    &[_]scanner.CaptureRegion{},
);

// Patterns previously ran in order:
//     AllocaProbe, SetMallocFree, OodleInit (combined), StateSize, Train, Decode, Encode
//
// If you need to verify the order or check new offsets/captures, see scripts/sigtool.py, latest output below:
// Offset       | ID       | Function         | Global | Local | Targets
// ----------------------------------------------------------------------------------------------------
// 0x001DDF49   | Probe    | Alloca_x64       | 29     | -     |
// 0x01D652B1   | Scan 4   | SharedSetWin     | 42922  | 29    | ->0x1CF7710
// 0x01D66F3C   | Scan 7   | EncodePtrs       | 1      | 1     | ->0x1E4B6B0, ->0x1E4B890
// 0x01D67181   | Scan 5a  | StateSizes       | 1      | 1     | ->0x1E4BEE0, ->0x1E4B6E0
// 0x01D67207   | Scan 5b  | TrainPtrs        | 1      | 1     | ->0x1E4B6F0, ->0x1E4C390
// 0x01D672AE   | Scan 1   | SetMallocFree    | 1      | 1     | ->0x1E42210
// 0x01D672FB   | Scan 2   | SharedSize       | 1      | 1     | ->0x1D67313, ->0x1E4D860
// 0x01D67318   | Scan 3   | WindowSize       | 118    | 1     | ->0x1E6731E
// 0x01D67583   | Scan 6   | DecodePtrs       | 1      | 1     | ->0x1E4B6A0, ->0x1E4B840
//
// Note: HtbitsSharedSize (Scan 2), WindowSize (Scan 3), and SharedSetWin (Scan 4) are resolved together by PatternOodleInit below.
// The standalone Scan 4 pattern has 42k+ global matches and cannot be used independently.

// Scan 1: SetMallocFree call
// Anchor: JNZ + two LEAs + CALL + MOV BYTE guard
//
// Index layout:
//   0     75 ??              JNZ short
//   2     48 8D 15 ????????  LEA rdx, [rip+??]
//   9     48 8D 0D ????????  LEA rcx, [rip+??]
//   16    E8 [?? ?? ?? ??]   CALL SetMallocFree  <- cap 0 at [17..20]
//   21    C6 05 ???????? 01  MOV BYTE PTR [rip+??], 1
pub const PatternSetMallocFree = scanner.Pattern(
    &[_]?u8{
        0x75, null, // JNZ short
        0x48, 0x8D, 0x15, null, null, null, null, // LEA rdx, [rip+??]
        0x48, 0x8D, 0x0D, null, null, null, null, // LEA rcx, [rip+??]
        0xE8, null, null, null, null, // CALL SetMallocFree
        0xC6, 0x05, null, null, null, null, 0x01, // MOV BYTE PTR, 1 (guard)
    },
    &[_]scanner.CaptureRegion{
        .{ .start = 17, .len = 4 }, // SetMallocFree rel32
    },
);

// Scan 2: OodleInit call
// Scan Init: Oodle initialisation sequence (htbits → SharedSize → WindowSize → SharedSetWindow)
// These instructions are sequential in the Oodle init function; matching them as one combined pattern avoids the
// false-positive problem that the standalone SharedSetWin pattern (42k matches) would have.
// The fixed instructions between captures are struct-offset accesses that are stable across patches.
//
//   0    75 ??                 JNZ short
//   2    B9 [?? ?? ?? ??]      MOV ecx, htbits     <- cap 0 at [3..6]
//   7    E8 [?? ?? ?? ??]      CALL SharedSize     <- cap 1 at [8..11]
//   12   45 33 C0              XOR r8d, r8d
//   15   33 D2                 XOR edx, edx
//   17   48 8B C8              MOV rcx, rax
//   20   E8 [?? ?? ?? ??]      CALL ...
//   25   4C 8B 43 58           MOV r10, [rbx+0x58]
//   29   41 B9 [?? ?? ?? ??]   MOV r9d, window size     <- cap 2 at [31..34]
//   35   BA [?? ?? ?? ??]      MOV edx, imm32
//   40   48 89 43 28           MOV [rbx+0x28], rax
//   44   48 8B C8              MOV rcx, rax
//   47   E8 [?? ?? ?? ??]      CALL SharedSetWindow     <- cap 3 at [48..51]
pub const PatternOodleInit = scanner.Pattern(
    &[_]?u8{
        0x75, null, // JNZ short
        0xB9, null, null, null, null, // MOV ecx, htbits
        0xE8, null, null, null, null, // CALL SharedSize
        0x45, 0x33, 0xC0, // XOR r8d, r8d
        0x33, 0xD2, // XOR edx, edx
        0x48, 0x8B, 0xC8, // MOV rcx, rax
        0xE8, null, null, null, null, // CALL ...
        0x4C, 0x8B, 0x43, 0x58, // MOV r10, [rbx+0x58]
        0x41, 0xB9, null, null, null, null, // MOV r9d, window size
        0xBA, null, null, null, null, // MOV edx, imm32
        0x48, 0x89, 0x43, 0x28, // MOV [rbx+0x28], rax
        0x48, 0x8B, 0xC8, // MOV rcx, rax
        0xE8, null, null, null, null, // CALL SharedSetWindow
    },
    &[_]scanner.CaptureRegion{
        .{ .start = 3, .len = 4 }, // htbits immediate
        .{ .start = 8, .len = 4 }, // SharedSize rel32
        .{ .start = 31, .len = 4 }, // window size immediate
        .{ .start = 48, .len = 4 }, // SharedSetWindow rel32
    },
);

// Scan 5: state sizes + train pointers
// Split at the {0,256} gap into 5a and 5b.

// Scan 5a: udp_state_size + tcp_state_size
//   0    75 04                JZ +4  (guard)
//   2    48 89 ?? ??          MOV [??], rcx
//   6    E8 [?? ?? ?? ??]     CALL udp_state_size  <- cap 0 at [7..10]
//   11   4C ?? ??             MOV/LEA r-something
//   14   E8 [?? ?? ?? ??]     CALL tcp_state_size  <- cap 1 at [15..18]
pub const PatternStateSizes = scanner.Pattern(
    &[_]?u8{
        0x75, 0x04, // JZ +4  (guard)
        0x48, 0x89, null, null, // MOV [rdx+??], rcx
        0xE8, null, null, null, null, // CALL GetUdpStateSize
        0x4C, null, null, // MOV r??, [r??+??]
        0xE8, null, null, null, null, // CALL GetTcpStateSize
    },
    &[_]scanner.CaptureRegion{
        .{ .start = 7, .len = 4 }, // udp_state_size rel32
        .{ .start = 15, .len = 4 }, // tcp_state_size rel32
    },
);

// Scan 5b: tcp_train + udp_train (after the {0,256} gap)
//   0    01                   (tail of prior instruction, used as anchor)
//   1    75 0A                JNZ +0xA
//   3    48 8B ??             MOV rcx, [??]
//   6    E8 [?? ?? ?? ??]     CALL tcp_train   <- cap 0 at [7..10]
//   11   EB 09                JMP +9
//   13   48 8B ?? 08          MOV rcx, [??+8]
//   17   E8 [?? ?? ?? ??]     CALL udp_train   <- cap 1 at [18..21]
pub const PatternTrainPtrs = scanner.Pattern(
    &[_]?u8{
        0x01, 0x75, 0x0A, // ADD/JNZ +0xA block
        0x48, 0x8B, null, // MOV rcx, [??]
        0xE8, null, null, null, null, // CALL tcp_train
        0xEB, 0x09, // JMP +9
        0x48, 0x8B, null, 0x08, // MOV rcx, [??+8]
        0xE8, null, null, null, null, // CALL udp_train
    },
    &[_]scanner.CaptureRegion{
        .{ .start = 7, .len = 4 }, // tcp_train rel32
        .{ .start = 18, .len = 4 }, // udp_train rel32
    },
);

// Scan 6: decode pointers
// No variable gaps - direct translation.
//
//   0    4D 85 D2             TEST r10, r10
//   3    74 0A                JZ +0xA
//   5    49 8B CA             MOV rcx, r10
//   8    E8 [?? ?? ?? ??]     CALL tcp_decode   <- cap 0 at [9..12]
//   13   EB 09                JMP +9
//   15   48 8B 49 08          MOV rcx, [rcx+8]
//   19   E8 [?? ?? ?? ??]     CALL udp_decode   <- cap 1 at [20..23]
pub const PatternDecodePtrs = scanner.Pattern(
    &[_]?u8{
        0x4D, 0x85, 0xD2, // TEST r10, r10
        0x74, 0x0A, // JZ +10
        0x49, 0x8B, 0xCA, // MOV rcx, r10
        0xE8, null, null, null, null, // CALL tcp_decode
        0xEB, 0x09, // JMP +9
        0x48, 0x8B, 0x49, 0x08, // MOV rcx, [rcx+8]
        0xE8, null, null, null, null, // CALL udp_decode
    },
    &[_]scanner.CaptureRegion{
        .{ .start = 9, .len = 4 }, // tcp_decode rel32
        .{ .start = 20, .len = 4 }, // udp_decode rel32
    },
);

// Scan 7: encode pointers
//
//   0    48 85 C0             TEST rax, rax
//   3    74 0D                JZ +0xD
//   5    48 8B C8             MOV rcx, rax
//   8    E8 [?? ?? ?? ??]     CALL tcp_encode   <- cap 0 at [9..12]
//   13   48 ?? ??             REX-prefixed instruction
//   16   EB 0B                JMP +0xB
//   18   48 8B 49 08          MOV rcx, [rcx+8]
//   22   E8 [?? ?? ?? ??]     CALL udp_encode   <- cap 1 at [23..26]
pub const PatternEncodePtrs = scanner.Pattern(
    &[_]?u8{
        0x48, 0x85, 0xC0, // TEST rax, rax
        0x74, 0x0D, // JZ +13
        0x48, 0x8B, 0xC8, // MOV rcx, rax
        0xE8, null, null, null, null, // CALL tcp_encode
        0x48, null, null, // MOV/LEA register
        0xEB, 0x0B, // JMP +11
        0x48, 0x8B, 0x49, 0x08, // MOV rcx, [rcx+8]
        0xE8, null, null, null, null, // CALL udp_encode
    },
    &[_]scanner.CaptureRegion{
        .{ .start = 9, .len = 4 }, // tcp_encode rel32
        .{ .start = 23, .len = 4 }, // udp_encode rel32
    },
);
