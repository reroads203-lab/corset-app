"""Brute-force byte-flag LZSS variants against a compressed X100F partition (ID5/ID6).

Usage: lz3.py 5_os_lib_compressed_flash0230000.lz

Scores each candidate decode of block 0 by whether its BL targets land on ARM
function prologues (strong "is this real code" oracle). Prints the best score.
Result on 2.12: nothing decodes past 0x1000 bytes -> the format is not a single
interleaved bit/byte-flag LZSS (literals are verbatim; control is a separate
stream). See REPORT.md section 4. Needs numpy.
"""
import sys, numpy as np
data=open(sys.argv[1],"rb").read()
HDR=0x14; BLK=0x4000
starts=[HDR, HDR+4]  # try with and without the 0f 00 00 00 preamble
def oracle(out):
    if len(out)<0x800: return 0.0,0
    w=np.frombuffer(out[:len(out)//4*4],dtype='<u4').astype(np.int64); n=len(w)
    push=((w&0xffff4000)==0xe92d4000)|(w==0xe52de004)
    bl=((w&0x0f000000)==0x0b000000)&((w>>28)==0xe)
    bi=np.nonzero(bl)[0]
    if len(bi)==0: return 0.0,int(push.sum())
    off=w[bi]&0xffffff; off=np.where(off&0x800000,off-0x1000000,off); tgt=bi+2+off
    inr=(tgt>=0)&(tgt<n)
    return (push[tgt[inr]].mean() if inr.any() else 0.0), int(push.sum())

def flag_lzss(src, msb, lit_is1, lbits, lhi, minm, dbase, m_msb):
    out=bytearray(); i=0; L=len(src); nbit=0; flag=0
    try:
        while i<L and len(out)<0x9000:
            if nbit==0: flag=src[i]; i+=1; nbit=8
            bit=(flag>>(7-(8-nbit)))&1 if msb else (flag>>(8-nbit))&1
            nbit-=1
            islit = (bit==1) if lit_is1 else (bit==0)
            if islit:
                out.append(src[i]); i+=1
            else:
                a=src[i]; b=src[i+1]; i+=2
                t=(a<<8|b) if m_msb else (a|b<<8)
                if lhi: ln=t>>(16-lbits); dist=t&((1<<(16-lbits))-1)
                else:   ln=t&((1<<lbits)-1); dist=t>>lbits
                ln+=minm; dist+=dbase
                if dist<=0 or dist>len(out): return None
                for _ in range(ln): out.append(out[-dist])
    except IndexError: pass
    return bytes(out)

globalbest=(0.0,None,0); hits=[]
for st in starts:
 blk0=data[st:st+BLK]
 for msb in (0,1):
  for lit_is1 in (0,1):
   for lbits in range(3,9):
    for lhi in (0,1):
     for minm in (1,2,3):
      for dbase in (0,1):
       for m_msb in (0,1):
         o=flag_lzss(blk0,msb,lit_is1,lbits,lhi,minm,dbase,m_msb)
         if not o or len(o)<0x1000: continue
         h,p=oracle(o)
         if h>globalbest[0]: globalbest=(h,(st,msb,lit_is1,lbits,lhi,minm,dbase,m_msb),len(o))
         if h>0.15 and p>=4: hits.append((round(h,3),p,len(o),(st,msb,lit_is1,lbits,lhi,minm,dbase,m_msb)))
hits.sort(reverse=True)
print("best overall:", globalbest[0], "params:", globalbest[1], "outlen:", globalbest[2])
for x in hits[:12]: print(x)
print("hits:",len(hits))
