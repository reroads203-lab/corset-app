"""Try classic ring-buffer LZSS (LHA-style and split-bit) variants on a compressed X100F partition.
Usage: lzss_ring.py 5_os_lib_compressed_flash0230000.lz  — scores block-0 decode by BL-hits-prologue.
Result on 2.12: no variant decodes to real code. See REPORT.md section 2.2. Needs numpy."""
import sys, numpy as np
data=open(sys.argv[1],"rb").read()
def score(o):
    if len(o)<0x400: return 0.0,0,len(o)
    w=np.frombuffer(o[:len(o)//4*4],dtype='<u4').astype(np.int64); n=len(w)
    push=((w&0xffff4000)==0xe92d4000)
    bl=((w&0x0f000000)==0x0b000000)&((w>>28)==0xe); bi=np.nonzero(bl)[0]
    if not len(bi): return 0.0,int(push.sum()),len(o)
    off=w[bi]&0xffffff; off=np.where(off&0x800000,off-0x1000000,off); tgt=bi+2+off
    inr=(tgt>=0)&(tgt<n)
    return (push[tgt[inr]].mean() if inr.any() else 0.0),int(push.sum()),len(o)

def lzss_ring(src, off, msb, lit1, posbits, lenbits, thr, fill, ringsz, ptypehi, lohi):
    out=bytearray(); ring=bytearray([fill])*ringsz; r=ringsz-((posbits+lenbits)//8+1)  # common init
    r=ringsz-18
    i=off; L=len(src); nbit=0; flag=0
    try:
        while i<L and len(out)<0x9000:
            if nbit==0: flag=src[i]; i+=1; nbit=8
            b=(flag>>(7-(8-nbit)))&1 if msb else (flag>>(8-nbit))&1
            nbit-=1
            islit=(b==1) if lit1 else (b==0)
            if islit:
                c=src[i]; i+=1; out.append(c); ring[r]=c; r=(r+1)%ringsz
            else:
                a=src[i]; b2=src[i+1]; i+=2
                if ptypehi:   # position in high bits
                    if lohi: pos=(a<<(8-(16-posbits)))|(b2>>(16-posbits)); ln=b2&((1<<(16-posbits))-1)
                    else: pos=(a|((b2>>lenbits)<<8))&((1<<posbits)-1); ln=b2&((1<<lenbits)-1)
                else:
                    pos=a|((b2&0xf0)<<4); ln=b2&0x0f   # classic LHA: pos=a + high nibble of b2, len=low nibble
                ln+=thr
                for _ in range(ln):
                    c=ring[pos%ringsz]; out.append(c); ring[r]=c; r=(r+1)%ringsz; pos=(pos+1)%ringsz
    except IndexError: pass
    return bytes(out)

best=(0.0,None,0,0)
for off in (0x14,0x18,0x0):
 for msb in (0,1):
  for lit1 in (0,1):
   for fill in (0x00,0x20):
     # classic LHA-style: pos=12bit, len=4bit(thr 3), ring 4096
     o=lzss_ring(data,off,msb,lit1,12,4,3,fill,4096,0,0)
     s,p,ln=score(o)
     if s>best[0]: best=(s,("classic",off,msb,lit1,fill),p,ln)
print("classic LHA-style best:", best)
# broader: pos/len splits
best2=(0.0,None,0,0)
for off in (0x14,0x18):
 for msb in (0,1):
  for lit1 in (0,1):
   for posbits in (10,11,12,13):
    for fill in (0x00,0x20):
     for lohi in (0,1):
       lenbits=16-posbits
       o=lzss_ring(data,off,msb,lit1,posbits,lenbits,2,fill,1<<posbits,1,lohi)
       s,p,ln=score(o)
       if s>best2[0]: best2=(s,("split",off,msb,lit1,posbits,fill,lohi),p,ln)
print("split ring best:", best2)
