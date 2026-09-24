# Draft post for the FujiHack community

Ready to paste into a GitHub issue at <https://github.com/fujihack/fujihack/issues>
or into the project's Discord. Written in English; sign-off is set to "kouno (Japan)".

---

**Title:** Compressed firmware partitions (X-Processor Pro era) use a simple 2KB-window LZSS — format solved, decompressor attached

Hi — kouno from Japan.

I have been statically analysing the FUJIFILM X100F firmware (Ver. 2.12, `FPUPDATE.DAT`)
and I think I have solved the compression used by the compressed partitions. The wiki
notes that the PTP/USB code is targeted for patching *because* it is not compressed like
other parts of the firmware, so this may be useful to the project.

### Summary

The compressed partitions are **not** an opaque hardware-only format. They are a plain
byte-oriented LZSS with a 2048-byte window, and can be decompressed in software.

### Format

Header: 0x14 bytes, five little-endian u32:

```
uncompressed_size, compressed_size, num_blocks, block_size (0x4000), flags
```

Body starts at offset 0x14 and is one continuous token stream:

```
control byte c:
  c <  0x80 : copy the next c bytes verbatim   (literal run)
  c >= 0x80 : read one more byte b
              val    = ((c & 0x7F) << 8) | b        # 15 bits
              length = val & 0x0F                   # 0..15
              dist   = val >> 4                     # 1..2047 bytes back
              copy `length` bytes from `dist` behind the current output
              (dist == 0 or length == 0 -> no-op)
```

Note `block_size` (0x4000) is the chunk size used when feeding the on-chip engine, not a
reset boundary — the LZ window runs continuously across the whole stream, which is why
decoding each 16KB block independently fails.

### How it was found

1. Whole ARM instruction sequences appear verbatim inside the compressed stream, so
   literals are copied uncompressed.
2. Parsing with "c < 0x80 = literal run of c bytes, c >= 0x80 = 2-byte match" consumes the
   input to exactly the last byte, and implies a mean match length of exactly 7.00.
3. Summing the low bits of every match value against the required match output total gave
   an exact fit (additive constant exactly 0) only for `length = val & 0xF`.

### Verification (X100F 2.12)

- Partition 5: 0x1EB675 -> **0x411D14** bytes (exact match with the header field)
- Partition 6: 0x3A0FDD -> **0x66F000** bytes (exact)
- 292 of 574 addresses that the main application calls inside partition 5 land on
  `push {..., lr}` prologues after decompression
- `strcmp`, `memcpy` and a printf-style logger appear as clean, textbook ARM at exactly
  the addresses the main application calls

### Tooling

I have a small stdlib-only Python decompressor plus an unpacker that parses the update
header, undoes the payload bit-inversion, reads the partition table (flash 0x120000 ->
RAM 0x950000) and writes every partition to its load address. Happy to share or to
contribute it in whatever form suits the project.

I have not touched repacking — the update header checksum is still unsolved for me, and I
have not modified or flashed anything.

For reference, the X100F memory map I ended up with:

| ID | load | size | flash | compressed |
|---|---|---|---|---|
| 0 | 0x00040000 | 0x1BB00 | 0x060000 | - |
| 1 | 0x001E0000 | 0x433C90 | 0x1270000 | - |
| 2 | 0x006F0000 | 0x90330 | 0x1830000 | - |
| 3 | 0x00950400 | 0x39A80 | 0x130000 | - |
| 4 | 0x00A50400 | 0x39A80 | 0x1B0000 | - |
| 5 | 0x00B51000 | 0x412000 | 0x230000 | yes |
| 6 | 0x0135C000 | 0x66F000 | 0x420000 | yes |
| 7 | 0x022FA000 | 0x7E9000 | 0x7D0000 | - |

Stage-1 boot loader is at flash 0x20000 and runs at address 0.

Let me know if this is useful, or if you would like me to test the decompressor against
another model's firmware — it should apply to any model using the same partition header.

kouno (Japan)
