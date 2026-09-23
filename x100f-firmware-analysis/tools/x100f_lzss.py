#!/usr/bin/env python3
"""Decompressor for the X-Processor Pro (Socionext Milbeaut) firmware LZ format
used by the compressed partitions (ID5/ID6) of the X100F firmware.

Format (solved by static analysis, see REPORT.md section 4):
  0x14-byte header: uncompressed_size, compressed_size, num_blocks,
                    block_size(0x4000), flags  (all little-endian u32; the last
                    field of the 5 is small).
  Body from offset 0x14, a continuous token stream with a 2048-byte sliding window:
    control byte c:
      c <  0x80 : copy the next c bytes verbatim (literal run)
      c >= 0x80 : back-reference. Read one more byte b.
                  val   = ((c & 0x7f) << 8) | b        # 15 bits
                  length = val & 0x0F                  # 0..15
                  dist   = val >> 4                    # 1..2047 (bytes back)
                  copy `length` bytes from `dist` behind the current output.
                  (dist==0 or length==0 => no-op)

Verified: ID5 -> 0x411D14 bytes, ID6 -> 0x66F000 bytes (exact), and the
functions the main app calls (strcmp, memcpy, a printf-like logger, ...) land
as clean ARM at their expected addresses.

usage: x100f_lzss.py IN.lz OUT.bin
"""
import struct
import sys


def parse_header(buf):
    usize, csize, nblk, blksz, flags = struct.unpack_from("<5I", buf, 0)
    return dict(uncompressed_size=usize, compressed_size=csize,
                num_blocks=nblk, block_size=blksz, flags=flags, header_size=0x14)


def decompress(buf):
    """buf is the whole .lz blob (including the 0x14 header)."""
    h = parse_header(buf)
    out = bytearray()
    i = h["header_size"]
    n = len(buf)
    while i < n:
        c = buf[i]; i += 1
        if c < 0x80:
            out += buf[i:i + c]; i += c
        else:
            val = ((c & 0x7F) << 8) | buf[i]; i += 1
            length = val & 0x0F
            dist = val >> 4
            if dist == 0 or length == 0 or dist > len(out):
                continue
            for _ in range(length):
                out.append(out[-dist])
    return bytes(out), h


if __name__ == "__main__":
    blob = open(sys.argv[1], "rb").read()
    data, h = decompress(blob)
    ok = len(data) == h["uncompressed_size"]
    open(sys.argv[2], "wb").write(data)
    print(f"{len(data):#x} bytes written (expected {h['uncompressed_size']:#x}) "
          f"{'OK' if ok else 'SIZE MISMATCH'}")
