"""Interactive analysis helpers for the decompressed X100F ID6 region (base 0x135C000).

Point X100F_REGIONS at the directory x100f_unpack.py wrote (default: ./out/regions),
then:  python3 -c "import sys;sys.path.insert(0,'tools');from ana6 import *; print(dis(0x17E347C))"

Provides: dis(), find_str(), refs_to(), func_start(), callers(), str_refs_in().
Needs numpy + capstone.
"""
import numpy as np, capstone, re, os
FW=os.environ.get("X100F_REGIONS","out/regions")
BASE=0x135C000
IMG=open(os.path.join(FW,"6_code_compressed_0135c000.bin"),"rb").read()
END=BASE+len(IMG)
W=np.frombuffer(IMG[:len(IMG)//4*4],dtype='<u4').astype(np.int64)
md=capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM); md.detail=False
ok=(W>>28)!=0xf
movw=ok&((W&0x0ff00000)==0x03000000); movt=ok&((W&0x0ff00000)==0x03400000)
imm=((W>>4)&0xf000)|(W&0xfff); rd=(W>>12)&0xf
_s=[];_v=[]
for i in np.nonzero(movt)[0]:
    for j in range(i-1,max(i-8,-1),-1):
        if movw[j] and rd[j]==rd[i]:
            _s.append(BASE+j*4); _v.append(int((imm[i]<<16)|imm[j])); break
ldr=ok&((W&0x0f7f0000)==0x051f0000)
for i in np.nonzero(ldr)[0]:
    off=int(W[i]&0xfff); t=i*4+8+(off if (W[i]>>23)&1 else -off)
    if 0<=t<len(W)*4 and t%4==0: _s.append(BASE+i*4); _v.append(int(W[t//4]))
XSRC=np.array(_s,np.int64); XVAL=np.array(_v,np.int64)
PUSH=((W&0xffff4000)==0xe92d4000)|(W==0xe52de004)
_bl=ok&((W&0x0f000000)==0x0b000000); _bi=np.nonzero(_bl)[0]
_o=W[_bi]&0xffffff; _o=np.where(_o&0x800000,_o-0x1000000,_o)
BL_SRC=BASE+_bi*4; BL_DST=BL_SRC+8+_o*4
def inimg(a): return BASE<=a<END
def cstr(a,m=200):
    if not inimg(a): return None
    o=a-BASE; e=IMG.find(b"\0",o,o+m)
    if e<0: return None
    s=IMG[o:e]
    try: s=s.decode('ascii')
    except: return None
    return s if s and all(32<=ord(c)<127 or c in '\n\r\t' for c in s) else None
def find_str(s):
    b=s.encode() if isinstance(s,str) else s
    return [BASE+m.start() for m in re.finditer(re.escape(b),IMG)]
def refs_to(a): return XSRC[XVAL==a]
def func_start(a):
    i=(a-BASE)//4
    while i>=0 and not PUSH[i]: i-=1
    return BASE+i*4 if i>=0 else None
def func_end(f,limit=0x4000):
    i=(f-BASE)//4+1
    for k in range(i,min(i+limit//4,len(W))):
        if PUSH[k]: return BASE+k*4
    return BASE+min(i+limit//4,len(W))*4
def callers(f): return BL_SRC[BL_DST==f]
def str_refs_in(f):
    e=func_end(f); m=(XSRC>=f)&(XSRC<e)
    return [(int(s),int(v),cstr(int(v))) for s,v in zip(XSRC[m],XVAL[m]) if cstr(int(v))]
def dis(start,end=None):
    end=end or func_end(start)
    c={int(s):int(v) for s,v in zip(XSRC[(XSRC>=start)&(XSRC<end)],XVAL[(XSRC>=start)&(XSRC<end)])}
    out=[]
    for ins in md.disasm(IMG[start-BASE:end-BASE],start):
        l=f"{ins.address:08x}: {ins.mnemonic:7} {ins.op_str}"
        if ins.address in c:
            v=c[ins.address]; s=cstr(v)
            l+=f"    ; {v:#x}"+(f' "{s[:50]}"' if s else "")
        out.append(l)
    return "\n".join(out)
