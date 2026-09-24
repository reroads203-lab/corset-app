"""Scan ARM code for classic calculation-defect patterns (whole-region, skipdata)."""
import sys, capstone
md=capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM); md.detail=False; md.skipdata=True
def scan(path, base, name, window=12):
    img=open(path,'rb').read()
    ins=[(i.address,i.mnemonic,i.op_str) for i in md.disasm(img, base)]
    div=[]; trunc=[]
    for k in range(len(ins)):
        a,m,o=ins[k]
        if m in ('udiv','sdiv'):
            parts=[p.strip() for p in o.split(',')]
            if len(parts)!=3: continue
            dv=parts[2]
            guarded=False
            for j in range(max(0,k-window),k):
                _,pm,po=ins[j]
                if pm in ('cmp','cmn','tst','teq','subs','orrs','movs','ands','rsbs') and dv in po:
                    guarded=True; break
                if pm in ('mov','movw') and po.startswith(dv+',') and '#' in po:
                    guarded=True; break
                if pm in ('udiv','sdiv','mul','ldr','ldrh','ldrb') and po.startswith(dv+','):
                    break
            if not guarded: div.append((a,m,o))
        if m in ('mul','mla','smull','umull'):
            dst=o.split(',')[0].strip()
            for j in range(k+1,min(len(ins),k+4)):
                _,qm,qo=ins[j]
                if qm=='uxth' and dst in qo: trunc.append(((a,m,o),(ins[j][0],qm,qo))); break
                if qm=='strh' and qo.startswith(dst+','): trunc.append(((a,m,o),(ins[j][0],qm,qo))); break
                if dst in qo: break
    print(f"--- {name}: {len(ins)} decoded | unguarded div: {len(div)} | mul->16bit: {len(trunc)}")
    for a,m,o in div[:8]: print(f"    DIV   {a:#010x}: {m} {o}")
    for (a,m,o),(b,qm,qo) in trunc[:8]: print(f"    TRUNC {a:#010x}: {m} {o} -> {qm} {qo}")
    return div,trunc
R=sys.argv[1]
for f,b,n in (("7_main_app_022fa000.bin",0x022FA000,"main app"),
              ("5_os_lib_compressed_00b51000.bin",0x00B51000,"ID5 os/lib"),
              ("6_code_compressed_0135c000.bin",0x0135C000,"ID6 code")):
    scan(f"{R}/{f}",b,n)
