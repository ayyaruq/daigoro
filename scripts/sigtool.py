"""
Signature diagnostic and export tool for FFXIV Oodle function scanning.

Scans a PE binary (ffxiv_dx11.exe) with x86-64 byte patterns to locate
Oodle compression functions and their parameters. Outputs a diagnostic
table showing match offsets and resolved call targets, and optionally
generates Zig source code for the daigoro signature module.

Usage:
    python sigtool.py <exe_path>              # diagnostic report
    python sigtool.py <exe_path> --zig        # emit Zig signature exports
    python sigtool.py <exe_path> --zig --hex  # use hex-string format in Zig output
"""

import argparse
import os
import re
import struct
import sys


def resolve_rel32(instruction_offset: int, rel32_bytes: bytes) -> int:
    """Decode a 32-bit little-endian relative displacement into an absolute address.

    The x86-64 CALL/JMP rel32 encoding stores the offset from the *end* of the
    instruction (offset + 4), so the target is ``instruction_offset + 4 + rel32``.
    Returns 0 if the bytes cannot be unpacked (e.g. out-of-bounds read).
    """
    try:
        rel32_val = struct.unpack('<i', rel32_bytes)[0]
        return instruction_offset + 4 + rel32_val
    except Exception:
        return 0


class SigChunk:
    """A contiguous fragment of a byte-pattern signature.

    Each chunk represents a fixed or wildcarded byte sequence with an
    assembly-level comment describing what it matches.

    Attributes:
        hex_bytes: Raw byte string. Bytes with value 0x2E (``'.'``) act as
                   single-byte wildcards in the pattern.
        comment: Human-readable ASM annotation for this chunk.
    """

    def __init__(self, hex_bytes: bytes, comment: str) -> None:
        self.hex_bytes: bytes = hex_bytes
        self.comment: str = comment


class Signature:
    """A named byte-pattern signature composed of multiple :class:`SigChunk` fragments.

    Captures mark byte ranges within the concatenated raw bytes whose resolved
    values (e.g. rel32 call targets, immediates) should be extracted after a match.

    Attributes:
        id_str: Short identifier used in diagnostic output (e.g. ``"Scan 1"``).
        name: Zig-safe name used for the generated constant (e.g. ``"SetMallocFree"``).
        chunks: Ordered list of :class:`SigChunk` fragments.
        captures: List of ``(offset, description)`` tuples describing capture regions.
        diagnostic_only: If ``True``, this signature is excluded from ``--zig`` output
                         (the combined pattern supersedes it).
    """

    def __init__(
        self,
        id_str: str,
        name: str,
        chunks: list[SigChunk],
        captures: list[tuple[int, str]],
        diagnostic_only: bool = False,
    ) -> None:
        self.id_str: str = id_str
        self.name: str = name
        self.chunks: list[SigChunk] = chunks
        self.captures: list[tuple[int, str]] = captures
        self.diagnostic_only: bool = diagnostic_only

    def get_raw_bytes(self) -> bytes:
        """Concatenate all chunks into a single bytestring for regex construction."""
        return b"".join(c.hex_bytes for c in self.chunks)

    def to_regex(self) -> bytes:
        """Build a regex pattern where ``0x2E`` bytes (``'.'``) become wildcards.

        Uses :func:`re.escape` on the raw bytes, then un-escapes the ``.``, ``{``,
        and ``}`` characters that were artificially inserted as wildcard markers.
        """
        return (
            re.escape(self.get_raw_bytes())
            .replace(b"\\.", b".")
            .replace(b"\\{", b"{")
            .replace(b"\\}", b"}")
        )


# --- SIGNATURE DEFINITIONS ---
sigs_def: list[Signature] = [
    Signature("Probe", "Alloca_x64", [
        SigChunk(b"\x48\x3D\x00\x10\x00\x00", "cmp rax, 1000h (page size check)"),
    ], []),
    Signature("Scan 1", "SetMallocFree", [
        SigChunk(b"\x75.", "JNZ short"),
        SigChunk(b"\x48\x8D\x15....", "LEA rdx, [rip+??]"),
        SigChunk(b"\x48\x8D\x0D....", "LEA rcx, [rip+??]"),
        SigChunk(b"\xE8....", "CALL SetMallocFree"),
        SigChunk(b"\xC6\x05....\x01", "MOV BYTE PTR, 1 (guard)"),
    ], [(17, "SetMallocFree rel32")]),
    # Scans 2/3/4 combined into OodleInit - used by lookup() instead of independent scans.
    # The standalone patterns are kept for diagnostic output only.
    Signature("Scan Init", "OodleInit", [
        SigChunk(b"\x75.",            "JNZ short"),
        SigChunk(b"\xB9....",         "MOV ecx, htbits"),
        SigChunk(b"\xE8....",         "CALL SharedSize"),
        SigChunk(b"\x45\x33\xC0",     "XOR r8d, r8d"),
        SigChunk(b"\x33\xD2",         "XOR edx, edx"),
        SigChunk(b"\x48\x8B\xC8",     "MOV rcx, rax"),
        SigChunk(b"\xE8....",         "CALL ..."),
        SigChunk(b"\x4C\x8B\x43\x58", "MOV r10, [rbx+0x58]"),
        SigChunk(b"\x41\xB9....",     "MOV r9d, window size"),
        SigChunk(b"\xBA....",         "MOV edx, imm32"),
        SigChunk(b"\x48\x89\x43\x28", "MOV [rbx+0x28], rax"),
        SigChunk(b"\x48\x8B\xC8",     "MOV rcx, rax"),
        SigChunk(b"\xE8....",         "CALL SharedSetWindow"),
    ], [
        (3,  "htbits immediate"),
        (8,  "SharedSize rel32"),
        (31, "window size immediate"),
        (48, "SharedSetWindow rel32"),
    ]),
    # Diagnostic-only standalone patterns below - not exported in --zig mode.
    Signature("Scan 2", "SharedSize", [
        SigChunk(b"\x75.", "JNZ short"),
        SigChunk(b"\xB9....", "MOV ecx, imm32 (htbits)"),
        SigChunk(b"\xE8....", "CALL SharedSize"),
        SigChunk(b"\x45\x33\xC0", "XOR r8d, r8d"),
        SigChunk(b"\x33\xD2", "XOR edx, edx"),
        SigChunk(b"\x48\x8B\xC8", "MOV rcx, rax"),
        SigChunk(b"\xE8....", "CALL ..."),
    ], [(3, "htbits immediate"), (8, "SharedSize rel32")], diagnostic_only=True),
    Signature("Scan 3", "WindowSize", [
        SigChunk(b"\x41\xB9....", "MOV r9d, imm32 (window size)"),
        SigChunk(b"\xBA", "MOV edx, ..."),
    ], [(2, "window size immediate")], diagnostic_only=True),
    Signature("Scan 4", "SharedSetWin", [
        SigChunk(b"\x48\x8B\xC8", "MOV rcx, rax"),
        SigChunk(b"\xE8....", "CALL SharedSetWindow"),
    ], [(4, "SharedSetWindow rel32")], diagnostic_only=True),
    Signature("Scan 5a", "StateSizes", [
        SigChunk(b"\x75\x04", "JNZ +4"),
        SigChunk(b"\x48\x89..", "MOV [rdx+??], rcx"),
        SigChunk(b"\xE8....", "CALL GetUdpStateSize"),
        SigChunk(b"\x4C..", "MOV r??, [r??+??]"),
        SigChunk(b"\xE8....", "CALL GetTcpStateSize"),
    ], [(7, "udp_state_size rel32"), (15, "tcp_state_size rel32")]),
    Signature("Scan 5b", "TrainPtrs", [
        SigChunk(b"\x01\x75\x0A", "ADD/JNZ block"),
        SigChunk(b"\x48\x8B.", "MOV register"),
        SigChunk(b"\xE8....", "CALL tcp_train"),
        SigChunk(b"\xEB\x09", "JMP +9"),
        SigChunk(b"\x48\x8B.\x08", "MOV register offset"),
        SigChunk(b"\xE8....", "CALL udp_train"),
    ], [(7, "tcp_train rel32"), (18, "udp_train rel32")]),
    Signature("Scan 6", "DecodePtrs", [
        SigChunk(b"\x4D\x85\xD2", "TEST r10, r10"),
        SigChunk(b"\x74\x0A", "JZ +10"),
        SigChunk(b"\x49\x8B\xCA", "MOV rcx, r10"),
        SigChunk(b"\xE8....", "CALL tcp_decode"),
        SigChunk(b"\xEB\x09", "JMP +9"),
        SigChunk(b"\x48\x8B\x49\x08", "MOV rcx, [rcx+8]"),
        SigChunk(b"\xE8....", "CALL udp_decode"),
    ], [(9, "tcp_decode rel32"), (20, "udp_decode rel32")]),
    Signature("Scan 7", "EncodePtrs", [
        SigChunk(b"\x48\x85\xC0", "TEST rax, rax"),
        SigChunk(b"\x74\x0D", "JZ +13"),
        SigChunk(b"\x48\x8B\xC8", "MOV rcx, rax"),
        SigChunk(b"\xE8....", "CALL tcp_encode"),
        SigChunk(b"\x48..", "MOV/LEA register"),
        SigChunk(b"\xEB\x0B", "JMP +11"),
        SigChunk(b"\x48\x8B\x49\x08", "MOV rcx, [rcx+8]"),
        SigChunk(b"\xE8....", "CALL udp_encode"),
    ], [(9, "tcp_encode rel32"), (23, "udp_encode rel32")]),
]


def format_hex_string_chunk(raw_bytes: bytes) -> str:
    """Convert raw pattern bytes to a space-separated hex string.

    Bytes equal to 0x2E (``'.'``) are rendered as ``"??"``; all other bytes
    are formatted as two-digit uppercase hex.
    """
    return " ".join(["??" if b == 46 else f"{b:02X}" for b in raw_bytes])


def run_diagnostic(file_path: str, export_zig: bool, hex_mode: bool) -> None:
    """Run the full diagnostic pipeline on a PE binary.

    1. Scan each :class:`Signature` against the file (globally and in a local
       neighbourhood around the SetMallocFree anchor).
    2. Print a table of match offsets, match counts, and resolved capture targets.
    3. If ``export_zig`` is ``True``, emit Zig ``Pattern*`` constant declarations
       for non-diagnostic signatures.

    Args:
        file_path: Path to the PE binary (ffxiv_dx11.exe).
        export_zig: If ``True``, print Zig source code for the daigoro scanner module.
        hex_mode: If ``True``, use ``scanner.ParsePattern`` hex-string format instead
                  of the ``?u8`` array literal format in Zig output.
    """
    if not os.path.exists(file_path): return print("File not found")
    with open(file_path, 'rb') as f: data = f.read()

    anchor_obj: Signature = next(s for s in sigs_def if s.id_str == "Scan 1")
    anchor_match: re.Match[bytes] | None = re.search(anchor_obj.to_regex(), data, re.DOTALL)
    anchor_pos: int | None = anchor_match.start() if anchor_match else None

    table_rows: list[tuple[int | None, str, str, int, int | str, str, Signature]] = []
    for s in sigs_def:
        regex: bytes = s.to_regex()
        g_matches: list[re.Match[bytes]] = list(re.finditer(regex, data, re.DOTALL))
        abs_start: int | None = None
        l_count: int | str = 0
        if s.id_str == "Probe":
            if g_matches: abs_start = g_matches[0].start()
            l_count = "-"
        elif anchor_pos:
            neighborhood = data[max(0, anchor_pos - 0x2000):anchor_pos + 0x8000]
            l_matches = list(re.finditer(regex, neighborhood, re.DOTALL))
            l_count = len(l_matches)
            if l_count > 0: abs_start = max(0, anchor_pos - 0x2000) + l_matches[0].start()

        targets = ""
        if abs_start is not None:
            res = [f"->0x{resolve_rel32(abs_start+off, data[abs_start+off:abs_start+off+4]):X}" for off, _ in s.captures]
            targets = ", ".join(res)
        table_rows.append((abs_start, s.id_str, s.name, len(g_matches), l_count, targets, s))

    table_rows.sort(key=lambda x: (x[0] is None, x[0]))

    print(f"DIAGNOSTIC REPORT: {os.path.basename(file_path)}")
    print(f"{'Offset':<12} | {'ID':<10} | {'Function':<16} | {'Global':<6} | {'Local':<5} | {'Targets'}")
    print("-" * 100)
    for off, sid, name, g, l, t, s_obj in table_rows:
        note = " (combined)" if s_obj.diagnostic_only else ""
        print(f"{f'0x{off:08X}' if off else '--------':<12} | {sid:<10} | {name:<16} | {g:<6} | {l:<5} | {t}{note}")

    if export_zig:
        print("\n// ZIG SIGNATURE EXPORT")
        for off, sid, name, g, l, t, s in table_rows:
            if off is None: continue
            if s.diagnostic_only: continue
            print(f"\n// {sid}: {name}")
            print(f"pub const Pattern{name} = scanner.Pattern(")
            if hex_mode:
                print("    scanner.ParsePattern(&[_][]const u8{")
                for c in s.chunks:
                    h_str = f"\"{format_hex_string_chunk(c.hex_bytes)}\","
                    print(f"        {h_str:<40} // {c.comment}")
                print("    }),")
            else:
                # Standard [ ]?u8 array format
                print("    &[_]?u8{")
                for c in s.chunks:
                    b_str = "".join(["null, " if b == 46 else f"0x{b:02X}, " for b in c.hex_bytes])
                    print(f"        {b_str:<40} // {c.comment}")
                print("    },")
            print("    &[_]scanner.CaptureRegion{")
            for off_val, comm in s.captures:
                print(f"        .{{ .start = {off_val}, .len = 4 }}, // {comm}")
            print("    },\n);")



if __name__ == "__main__":
    if sys.version_info < (3, 11):
        sys.exit("Error: Python 3.11 or higher is required.")

    parser = argparse.ArgumentParser(
        description="Scan a PE binary for FFXIV Oodle function signatures."
    )
    parser.add_argument("file", help="Path to ffxiv_dx11.exe")
    parser.add_argument("--zig", action="store_true", help="Emit Zig scanner pattern exports")
    parser.add_argument("--hex", action="store_true", help="Use hex-string format in Zig output")
    args = parser.parse_args()
    run_diagnostic(args.file, args.zig, args.hex)
