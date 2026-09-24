"""Validate ARM jump-table bound checks for off-by-one errors.

Pattern:  cmp rX, #N ; ldrls pc, [pc, rX, lsl #2] ; b default ; <N+1 target words>
A correct table holds N+1 plausible code pointers. If the LAST allowed entry is
not a plausible target while the earlier ones are, the bound check admits one
index too many -> the dispatcher jumps to data.
"""
import sys, numpy as np
def scan(path, base, name):
    img=open(path,'rb').read()
    W=np.frombuffer(img[:len(img)//4*4],dtype='<u4').astype(np.int64)
    n=len(W); lo,hi=base,base+len(img)
    # ldrls pc,[pc,rX,lsl#2] == 0x979ff10X  (cond=9 LS, ldr pc, [pc, rX lsl 2])
    cand=np.nonzero((W & 0xfffffff0)==0x979ff100)[0]
    findings=[]
    for i in cand:
        rx=int(W[i]&0xf)
        # find the cmp rX,#N in the few instructions before
        N=None
        for j in range(i-1,max(i-6,-1),-1):
            w=int(W[j])
            if (w & 0x0ff0f000)==0x03500000 and ((w>>16)&0xf)==rx:   # cmp rX, #imm
                imm=w&0xff; rot=((w>>8)&0xf)*2
                N=((imm>>rot)|(imm<<(32-rot)))&0xffffffff if rot else imm
                break
        if N is None or N>256: continue
        tb=i+2   # table starts after the ldrls and the following b
        if tb+N+1>n: continue
        tgts=[int(W[tb+k]) for k in range(N+1)]
        def plausible(t):
            if not (lo<=t<hi) or t%4: return False
            k=(t-base)//4
            return (int(W[k])>>28)!=0xf      # decodes with a valid condition field
        ok=[plausible(t) for t in tgts]
        if all(ok): continue
        bad=[k for k,v in enumerate(ok) if not v]
        # interesting when only the final entries are bad (classic <= vs < )
        findings.append((base+i*4, N, bad, tgts[-1], sum(ok)))
    print(f"--- {name}: {len(cand)} jump tables, {len(findings)} with implausible entries")
    for addr,N,bad,last,nok in findings[:15]:
        tag="LAST-ONLY (off-by-one?)" if bad==[N] else ""
        print(f"  {addr:#010x} bound<={N} ({N+1} entries) ok={nok} badidx={bad[:6]} last={last:#010x} {tag}")
    return findings
R=sys.argv[1]
scan(f"{R}/7_main_app_022fa000.bin",0x022FA000,"main app")
scan(f"{R}/5_os_lib_compressed_00b51000.bin",0x00B51000,"ID5 os/lib")
scan(f"{R}/6_code_compressed_0135c000.bin",0x0135C000,"ID6 code")
