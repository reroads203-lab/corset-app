# Ghidra script: lay out the X100F firmware memory map and apply known labels.
# @category Fujifilm
#
# Works with both Jython (Ghidra <= 11) and PyGhidra.
#
# 1. Run tools/x100f_unpack.py FPUPDATE.DAT OUT first.
# 2. In Ghidra: File > Import > OUT/regions/7_main_app_022fa000.bin
#      Format: Raw Binary, Language: ARM:LE:32:v7 (default compiler),
#      Options > Base Address: 0x022fa000. Do not auto-analyze yet.
# 3. Run this script and pick the OUT directory. It adds the other plaintext
#    partitions, placeholder blocks for the two compressed partitions and
#    labels/comments for the functions identified in REPORT.md.
# 4. Run Auto Analyze.
import json
import os

from java.io import FileInputStream

LABELS = {
    # stage-1 boot loader (flash 0x20000, runs at 0)
    0x00000000: ("boot_vectors", "ARM exception vectors (ldr pc, [pc, #0x18] x8)"),
    0x00000100: ("boot_reset", None),
    0x000008AC: ("boot_load_part0", "Loads partition 0 (ThreadX boot stage) to 0x40000"),
    0x00000910: ("boot_load_part5_hwdec", "Loads compressed partition 5 through the HW decompressor"),
    0x000009A0: ("boot_load_updaters", "Loads partitions 3/4 (updater A/B)"),
    0x00000A68: ("ptable_find", "Find partition entry by id (0x24-byte stride, 0xFF ends)"),
    0x00009C04: ("hwdec_poll_done", "Polls 0xFFF80028 bit0"),
    0x00009C40: ("hwdec_stop", "Writes 0x84000400 to 0xFFF80020"),
    0x00009E0C: ("hwdec_init", "Enables peripheral 0x17, sets dst/src"),
    0x00009E7C: ("hwdec_feed_cb", "Per-chunk callback passed to flash_read"),
    0x00009EA4: ("hwdec_finish", None),
    0x0000A0B8: ("flash_check_signature", "Checks FFFFFFFF/00000000/55555555/AAAAAAAA at 0xF0000000"),
    0x0000A7C4: ("flash_read", "(dst, flash_addr, size, chunk_cb)"),
    0x0000B210: ("flash_off_to_addr", None),
    # partition 0: ThreadX boot stage
    0x00040000: ("stage0_start", "Partition 0: ThreadX SMP/Cortex-A7 G5.6.2.5.0 boot stage"),
    # partition 3: updater
    0x00950000: ("partition_table", "Copied from flash 0x120000 by the boot loader"),
    0x00950400: ("updater_a_start", "Partition 3: firmware updater (FAT/SD access)"),
    # partition 5 (compressed): library calls from main_app
    0x00C1D860: ("dbg_log", "(tag, fmt, ...) - inferred from call sites"),
    0x00CCDDBC: ("strcmp", "inferred from call sites"),
    0x00CCE3C0: ("memcpy_like", "(dst, src, n) - inferred from call sites"),
    # main application
    0x022FA000: ("main_app_start", "Partition 7 text (0x5b8000) + data sections"),
    0x02302104: ("ui_screen_dispatch", "handler = table[(id-1)*0x1c + 8] at 0x026098E0"),
    0x02304A84: ("ui_msg_loop", "Caller of ui_screen_dispatch"),
    0x023096E4: ("ui_debug_version_info", "Software Version / EEP Adjust Date / Script Version / OSTIME"),
    0x0230A100: ("debug_console_cmd", "COMGETVAL / LASTDISPID / REMREL / MFDIST / CONTINUOUS / Hello world!"),
    0x0231F79C: ("ui_osd_debug_mode_screen", "OSD DEBUG MODE SCREEN SELECT (screen id 0xA06, UI msg 0x47)"),
    0x023233B4: ("osd_dbg_print", "(col, row, str)"),
    0x026098C4: ("ui_screen_table", "79 records of 7 words: handler, 0, flag, 0, screen_id, 0, 0"),
    0x0298C844: ("wpa_printf", "wpa_supplicant debug print"),
}


def add_block(mem, name, start, path=None, size=None):
    addr = toAddr(start)
    if mem.getBlock(addr) is not None:
        print("skip %s: %s already mapped" % (name, addr))
        return
    if path:
        size = os.path.getsize(path)
        mem.createInitializedBlock(name, addr, FileInputStream(path), size, monitor, False)
    else:
        mem.createUninitializedBlock(name, addr, size, False)
    print("mapped %-22s %s +%#x" % (name, addr, size))


out = askDirectory("x100f_unpack.py output directory", "Use").getAbsolutePath()
mm = json.load(open(os.path.join(out, "memory_map.json")))
mem = currentProgram.getMemory()

add_block(mem, "boot_stage1", 0, os.path.join(out, mm["boot_stage1"]["file"]))
for p in mm["partitions"]:
    pid, load = p["id"], p["load"]
    if pid in (0, 3, 4):
        add_block(mem, p["name"], load, os.path.join(out, p["file"]))
    elif pid in (5, 6):
        # compressed on flash; code + bss occupy [load, end + bss)
        add_block(mem, p["name"] + "_unavailable", load, size=p["end"] + p["bss"] - load)
add_block(mem, "hwdec_regs", 0xFFF80000, size=0x100)

for a, (name, cmt) in sorted(LABELS.items()):
    addr = toAddr(a)
    if mem.getBlock(addr) is None:
        continue
    createLabel(addr, name, True)
    if cmt:
        setPlateComment(addr, cmt)
print("done: %d labels" % len(LABELS))
