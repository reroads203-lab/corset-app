#!/usr/bin/env python3
"""Quick static cross-references for a raw ARM (A32) region. Needs numpy + capstone.

  arm_xrefs.py REGION.bin BASE --str "OSD DEBUG MODE"   who references a string
  arm_xrefs.py REGION.bin BASE --func 0x0231F79C          disassemble a function (strings annotated) + callers
  arm_xrefs.py REGION.bin BASE --find-base                estimate BASE from movw/movt + literal pointers

Constants are recovered from movw/movt pairs (how this firmware builds almost all
addresses) and PC-relative literal loads. Function starts are found by scanning
back to the nearest push {..., lr}.
"""
import argparse
import re

import capstone
import numpy as np


class Region:
    def __init__(self, path, base):
        self.img = open(path, "rb").read()
        self.base, self.end = base, base + len(self.img)
        w = np.frombuffer(self.img[:len(self.img) // 4 * 4], dtype="<u4").astype(np.int64)
        self.w = w
        ok = (w >> 28) != 0xF
        movw = ok & ((w & 0x0FF00000) == 0x03000000)
        movt = ok & ((w & 0x0FF00000) == 0x03400000)
        imm = ((w >> 4) & 0xF000) | (w & 0xFFF)
        rd = (w >> 12) & 0xF
        src, val = [], []
        for i in np.nonzero(movt)[0]:
            for j in range(i - 1, max(i - 8, -1), -1):
                if movw[j] and rd[j] == rd[i]:
                    src.append(base + j * 4); val.append(int((imm[i] << 16) | imm[j])); break
        ldr = ok & ((w & 0x0F7F0000) == 0x051F0000)
        for i in np.nonzero(ldr)[0]:
            off = int(w[i] & 0xFFF)
            tgt = i * 4 + 8 + (off if (w[i] >> 23) & 1 else -off)
            if 0 <= tgt < len(w) * 4 and tgt % 4 == 0:
                src.append(base + i * 4); val.append(int(w[tgt // 4]))
        self.xsrc, self.xval = np.array(src, np.int64), np.array(val, np.int64)
        bl = ok & ((w & 0x0F000000) == 0x0B000000)
        bi = np.nonzero(bl)[0]
        off = w[bi] & 0xFFFFFF
        off = np.where(off & 0x800000, off - 0x1000000, off)
        self.bl_src = base + bi * 4
        self.bl_dst = self.bl_src + 8 + off * 4
        self.push = ((w & 0xFFFF4000) == 0xE92D4000) | (w == 0xE52DE004)
        self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

    def cstr(self, a, maxlen=160):
        if not self.base <= a < self.end:
            return None
        o = a - self.base
        e = self.img.find(b"\0", o, o + maxlen)
        s = self.img[o:e] if e > o else b""
        return s.decode() if s and all(32 <= c < 127 or c in (9, 10, 13) for c in s) else None

    def func_start(self, a):
        i = (a - self.base) // 4
        while i >= 0 and not self.push[i]:
            i -= 1
        return self.base + i * 4

    def func_end(self, f, limit=0x4000):
        i = (f - self.base) // 4 + 1
        for k in range(i, min(i + limit // 4, len(self.w))):
            if self.push[k]:
                return self.base + k * 4
        return self.base + min(i + limit // 4, len(self.w)) * 4

    def dis(self, f):
        e = self.func_end(f)
        consts = dict(zip(self.xsrc.tolist(), self.xval.tolist()))
        for ins in self.md.disasm(self.img[f - self.base:e - self.base], f):
            line = "%08x: %-7s %s" % (ins.address, ins.mnemonic, ins.op_str)
            v = consts.get(ins.address)
            if v is not None:
                s = self.cstr(v)
                line += "    ; %#x%s" % (v, ' "%s"' % s[:60] if s else "")
            print(line)


def find_base(path):
    img = open(path, "rb").read()
    r = Region(path, 0)
    cands = np.unique(np.concatenate([r.xval, r.w]))
    strs = np.array([m.start() for m in re.finditer(rb"[\x20-\x7e]{6,}\x00", img)], np.int64)
    rng = np.random.default_rng(0)
    a = rng.choice(cands, size=min(3000, len(cands)), replace=False)
    b = rng.choice(strs, size=min(3000, len(strs)), replace=False)
    diff = (a[:, None] - b[None, :]).ravel()
    # instruction words (0xE...) masquerade as pointers; bases are page aligned in this firmware
    diff = diff[(diff >= 0) & (diff < 0xE0000000) & (diff % 0x100 == 0)]
    vals, cnt = np.unique(diff, return_counts=True)
    top = vals[np.argsort(-cnt)[:50]]
    scored = sorted(((int(np.isin(strs + v, cands).sum()), int(v)) for v in top), reverse=True)
    for hits, v in scored[:5]:
        print("base %#010x  strings referenced=%d/%d" % (v, hits, len(strs)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("region"); ap.add_argument("base", nargs="?", default="0")
    ap.add_argument("--str"); ap.add_argument("--func"); ap.add_argument("--find-base", action="store_true")
    a = ap.parse_args()
    if a.find_base:
        return find_base(a.region)
    r = Region(a.region, int(a.base, 0))
    if a.str:
        for m in re.finditer(re.escape(a.str.encode()), r.img):
            addr = r.base + m.start()
            refs = r.xsrc[r.xval == addr].tolist()
            print("%#010x %r" % (addr, a.str))
            for s in refs:
                print("    ref %#010x in func %#010x" % (s, r.func_start(s)))
    if a.func:
        f = int(a.func, 0)
        r.dis(f)
        print("callers:", ["%#010x" % c for c in r.bl_src[r.bl_dst == f].tolist()])


if __name__ == "__main__":
    main()
