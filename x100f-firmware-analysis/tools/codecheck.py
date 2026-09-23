"""Is a region real ARM/Thumb code? Capstone decode rate alone is weak (random bytes decode too),
so also check whether BL targets land on function prologues."""
import sys, numpy as np, capstone
def arm_stats(b, base):
    w = np.frombuffer(b[:len(b)//4*4], dtype='<u4').astype(np.int64); n = len(w)
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    samp = b[:min(len(b), 0x40000)]
    ok = sum(1 for _ in md.disasm_lite(samp, 0)) if samp else 0  # stops at first invalid
    valid = 0
    for i in range(0, len(samp), 4):
        if next(md.disasm_lite(samp[i:i+4], 0), None): valid += 1
    push = ((w & 0xffff4000) == 0xe92d4000) | (w == 0xe52de004)
    bl = ((w & 0x0f000000) == 0x0b000000) & ((w >> 28) == 0xe)
    bi = np.nonzero(bl)[0]; off = w[bi] & 0xffffff; off = np.where(off & 0x800000, off - 0x1000000, off)
    tgt = bi + 2 + off
    inr = (tgt >= 0) & (tgt < n)
    hit = push[tgt[inr]].mean() if inr.any() else 0
    return valid / max(1, len(samp)//4), push.sum(), len(bi), inr.mean() if len(bi) else 0, hit
def thumb_stats(b):
    h = np.frombuffer(b[:len(b)//2*2], dtype='<u2').astype(np.int64); n = len(h)
    tpush = (h & 0xff00) == 0xb500                     # push {..., lr}
    t2push = (h == 0xe92d)                             # push.w
    hi = (h[:-1] & 0xf800) == 0xf000; lo = (h[1:] & 0xd000) == 0xd000   # BL: f000 xxxx / f800-ish
    idx = np.nonzero(hi & lo)[0]
    S = (h[idx] >> 10) & 1; imm10 = h[idx] & 0x3ff; J1 = (h[idx+1] >> 13) & 1; J2 = (h[idx+1] >> 11) & 1; imm11 = h[idx+1] & 0x7ff
    I1 = 1 - (J1 ^ S); I2 = 1 - (J2 ^ S)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    off = np.where(S == 1, off - (1 << 25), off)
    tgt = idx + 2 + off // 2
    inr = (tgt >= 0) & (tgt < n)
    fstart = tpush | t2push
    hit = fstart[tgt[inr]].mean() if inr.any() else 0
    return int(tpush.sum()), len(idx), inr.mean() if len(idx) else 0, hit
print(f"{'region':34} {'ARMvalid':>8} {'push':>6} {'BL':>7} {'BLin':>5} {'BL->func':>8} | {'Tpush':>6} {'T-BL':>7} {'T-BLin':>6} {'T-BL->func':>10}")
for name, fn, base in [(a.split('=')[0], a.split('=')[1].split('@')[0], int(a.split('@')[1], 0)) for a in sys.argv[1:]]:
    b = open(fn, "rb").read()
    v, p, nbl, inr, hit = arm_stats(b, base)
    tp, tbl, tinr, thit = thumb_stats(b)
    print(f"{name:34} {v:8.2%} {p:6d} {nbl:7d} {inr:5.0%} {hit:8.1%} | {tp:6d} {tbl:7d} {tinr:6.0%} {thit:10.1%}")
