#!/usr/bin/env python3
"""Unpack a Fujifilm X-Processor Pro era firmware update file (X100F FPUPDATE.DAT).

Stdlib only. Steps:
  1. Parse the 0x214-byte update header (model codes, version, checksum).
  2. Undo the obfuscation: every payload byte is bit-inverted (~b).
  3. Treat the decoded payload as a flash image: payload[0x48] == flash 0xF0000000.
  4. Parse the partition table the boot loader reads from flash 0x120000.
  5. Write every partition to OUTDIR/regions/ and a memory map to OUTDIR/memory_map.json.

Compressed partitions (flag == 1) are decompressed with x100f_lzss and written
to their load address; the raw .lz blob is kept alongside for reference.

usage: x100f_unpack.py FPUPDATE.DAT OUTDIR
"""
import json
import os
import struct
import sys

from x100f_lzss import decompress as lzss_decompress

CODE_SIZE = {1: 64, 2: 128, 3: 512, 4: 512, 5: 512, 6: 512, 8: 512}
FLASH_BASE = 0xF0000000
FLASH_SKEW = 0x48            # payload offset of flash address 0xF0000000
PTABLE_FLASH = 0x120000      # boot loader copies 0x400 bytes from here to RAM 0x950000
PTABLE_RAM = 0x950000
PART_ENTRY = struct.Struct("<9I")
INVERT = bytes(255 - i for i in range(256))

# Names inferred from strings and code in each partition (see REPORT.md).
PART_NAMES = {
    0: "boot_stage_threadx",
    1: "ui_graphics",
    2: "resource_2",
    3: "updater_a",
    4: "updater_b",
    5: "os_lib_compressed",
    6: "code_compressed",
    7: "main_app",
}


def parse_header(buf):
    kind = struct.unpack_from("<I", buf, 0)[0]
    cs = CODE_SIZE[kind]
    raw = buf[4:4 + cs]
    # Model codes are stored as ASCII hex of ASCII digits, 8 digits per model.
    digits = bytes(raw[1::2]).decode("ascii", "replace")
    models = [digits[i:i + 8] for i in range(0, len(digits), 8)]
    models = [m for m in models if m.strip("0\0")]
    v1, v2, csum, dev = struct.unpack_from("<IIII", buf, 4 + cs)
    return {
        "header_type": kind,
        "model_codes": models,
        "version": f"{v1:x}.{v2:02x}",
        "checksum": f"{csum:#010x}",
        "device_type": dev,
        "header_size": cs + 20,
    }


def flash(payload, off, size):
    p = FLASH_SKEW + off
    return payload[p:p + size]


def parse_partitions(payload):
    tbl = flash(payload, PTABLE_FLASH, 0x400)
    first_ptr = struct.unpack_from("<I", tbl, 0)[0]
    main_ptr = struct.unpack_from("<I", tbl, 4)[0]
    parts = []
    pos = first_ptr - PTABLE_RAM
    while pos + PART_ENTRY.size <= len(tbl) and tbl[pos] != 0xFF:
        pid, load, size, end, bss, foff, fsize, hdr, comp = PART_ENTRY.unpack_from(tbl, pos)
        if fsize:
            parts.append(dict(id=pid, name=PART_NAMES.get(pid, f"part{pid}"), load=load, size=size,
                              end=end, bss=bss, flash_off=foff, flash_size=fsize,
                              hdr=hdr, compressed=bool(comp)))
        pos += PART_ENTRY.size
    # Second table: main application sections (text + data), pointed to by word 1.
    sections = []
    mpos = main_ptr - PTABLE_RAM
    _, main_load, main_size, _, text_load, text_size, _, _ = struct.unpack_from("<8I", tbl, mpos)
    sections.append(dict(kind="text", load=text_load, size=text_size))
    spos = mpos + 0x20
    while spos + 16 <= len(tbl):
        sid, idx, load, size = struct.unpack_from("<4I", tbl, spos)
        if idx == 0xFF or sid == 0:
            break
        sections.append(dict(kind=f"section_{sid:#x}", load=load, size=size))
        spos += 0x18
    for p in parts:
        if p["id"] == 7:
            p.update(load=main_load, size=main_size, end=main_load + main_size, sections=sections)
    return parts


def parse_comp_header(blob):
    usize, csize, nblk, blksz, unk = struct.unpack_from("<5I", blob, 0)
    return dict(uncompressed_size=usize, compressed_size=csize, blocks=nblk,
                block_size=blksz, unknown=unk, stream_first_word=struct.unpack_from("<I", blob, 0x14)[0])


def main():
    src, out = sys.argv[1], sys.argv[2]
    buf = open(src, "rb").read()
    hdr = parse_header(buf)
    payload = buf[hdr["header_size"]:].translate(INVERT)
    os.makedirs(os.path.join(out, "regions"), exist_ok=True)
    open(os.path.join(out, "payload_decoded.bin"), "wb").write(payload)

    parts = parse_partitions(payload)
    for p in parts:
        blob = flash(payload, p["flash_off"], p["flash_size"])
        if p["compressed"]:
            p["comp_header"] = parse_comp_header(blob)
            lz = blob[:p["comp_header"]["compressed_size"]]
            # Decompress to the region's load address (format solved; see x100f_lzss.py).
            data, _ = lzss_decompress(lz)
            p["decompressed_size"] = len(data)
            fn = f"{p['id']}_{p['name']}_{p['load']:08x}.bin"
            open(os.path.join(out, "regions", fn), "wb").write(data)
            # Keep the raw compressed blob too, for reference.
            lzfn = f"{p['id']}_{p['name']}_flash{p['flash_off']:07x}.lz"
            open(os.path.join(out, "regions", lzfn), "wb").write(lz)
            p["file"] = f"regions/{fn}"
            p["lz_file"] = f"regions/{lzfn}"
            continue
        # Region data starts at the partition's flash offset; the load address maps to it.
        blob = blob[:p["size"]]
        fn = f"{p['id']}_{p['name']}_{p['load']:08x}.bin"
        open(os.path.join(out, "regions", fn), "wb").write(blob)
        p["file"] = f"regions/{fn}"

    # Stage-1 boot loader: flash 0x20000, executes at address 0 (ARM vector table).
    boot = flash(payload, 0x20000, 0xEEB8)
    open(os.path.join(out, "regions", "boot_stage1_00000000.bin"), "wb").write(boot)

    mm = {"header": hdr, "flash_base": f"{FLASH_BASE:#x}", "payload_to_flash_skew": FLASH_SKEW,
          "partition_table": {"flash_off": f"{PTABLE_FLASH:#x}", "ram": f"{PTABLE_RAM:#x}"},
          "partitions": parts,
          "boot_stage1": {"flash_off": "0x20000", "load": "0x0", "file": "regions/boot_stage1_00000000.bin"}}
    with open(os.path.join(out, "memory_map.json"), "w") as f:
        json.dump(mm, f, indent=2, default=lambda v: v)

    print(f"model codes : {' '.join(hdr['model_codes'])}")
    print(f"version     : {hdr['version']}   header checksum {hdr['checksum']}")
    print(f"{'id':>2} {'name':20} {'load':>10} {'size':>9} {'flash':>9} {'comp':>4}")
    for p in parts:
        print(f"{p['id']:>2} {p['name']:20} {p['load']:#010x} {p['size']:#9x} {p['flash_off']:#9x} {'yes' if p['compressed'] else '':>4}")
        for s in p.get("sections", []):
            print(f"{'':23}{s['load']:#010x} {s['size']:#9x}  {s['kind']}")


if __name__ == "__main__":
    main()
