import logging
import os
import sys
import elftools
import capstone
import subprocess
from elftools.elf.elffile import ELFFile

l = logging.getLogger("unstrip")
l.setLevel(logging.INFO)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

functions = [
    "__libc_start_main",
    "puts", "printf", "memcpy",
    "strcpy", "strcmp", "__strcmp_ia32", "strlen",
    "memset", "__memset_ia32", "memcmp", "__memcmp_ia32",
    "malloc", "free", "calloc",
    "__read_nocancel", "__write_nocancel", "read", "write",
]
dependency = {
    "strcmp": "__strcmp_ia32",
    "memcmp": "__memcmp_ia32",
    "memset": "__memset_ia32",
    "read": "__read_nocancel",
    "write": "__write_nocancel",
}
containing = {
    "__read_nocancel": "\xB8\x03\x00\x00\x00",
    "__write_nocancel": "\xB8\x04\x00\x00\x00",
}

def match(a, t, o):
    if o < 0 or len(a) < len(t) + o:
        return False
    for i in range(len(t)):
        if t[i] != '\x00' and a[o + i] != t[i]:
            return False
    return True

def recognize(data, base, addr, templates, recognized):
    if addr not in recognized:
        recognized[addr] = None
        for name, t in templates:
            off = addr - base
            if len(data) - off < len(t):
                continue
            if match(data, t, off):
                inc = containing.get(name)
                if inc:
                    if inc not in data[off: off + len(t)]:
                        continue
                dep = dependency.get(name)
                if dep:
                    refs = set()
                    for i in md.disasm(data[off: off + len(t)], addr):
                        ref = recognize(data, base, i.address, templates, recognized)
                        if ref:
                            refs.add(ref)
                        target = None
                        if i.id in [capstone.x86_const.X86_INS_JMP, capstone.x86_const.X86_INS_CALL]:
                            if i.operands[0].type == capstone.x86_const.X86_OP_IMM:
                                target = i.operands[0].imm + i.address
                        elif i.id in [capstone.x86_const.X86_INS_LEA]:
                            if i.operands[1].type == capstone.x86_const.X86_OP_MEM:
                                target = i.operands[1].value.mem.disp
                        if target != None:
                            ref = recognize(data, base, target, templates, recognized)
                            if ref:
                                refs.add(ref)
                    if dep not in refs:
                        continue
                l.info("%08X: %s", base + off, name)
                break
        else:
            name = None
        recognized[addr] = name
    return recognized[addr]

def unstrip(path, ref):
    templates = []
    recognized = {}

    l.debug("analyze ref...")
    with open(ref, "rb") as f:
        obj = ELFFile(f)
        symbols = []
        sections = []
        for sec in obj.iter_sections():
            sections.append(sec)
            if sec.header['sh_type'] != 'SHT_SYMTAB':
                continue
            for sym in sec.iter_symbols():
                if sym.name not in functions:
                    continue
                size = sym.entry["st_size"]
                if size < 100:
                    pass # continue
                if sym.entry['st_info']['type'] not in ["STT_LOOS", "STT_FUNC"] or sym.entry['st_info']['bind'] not in ['STB_GLOBAL','STB_WEAK', 'STB_LOCAL']:
                    continue
                symbols.append(sym)
        for sym in symbols:
            size = sym.entry["st_size"]
            l.info("%s:\t%d bytes", sym.name, size)
            sec = sections[sym.entry['st_shndx']]
            base = sec.header['sh_addr']
            addr = sym.entry["st_value"]
            data = sec.data()
            off = addr - base
            raw = data[off: off + size]
            t = ""
            off = 0
            for i in md.disasm(raw, addr):
                t += raw[off] + '\x00' * (i.size - 1)
                off += i.size
                #l.info("0x%x:\t%s\t%s", i.address, i.mnemonic, i.op_str)
                #for o in i.operands:
                #    if o.type == capstone.x86_const.X86_OP_MEM:
                #        o.value.mem.disp = 0
            templates.append((sym.name, t))
        del symbols
        del sections

    l.info("analyze elf...");
    elf = ELFFile(open(path, "rb"))
    for sec in elf.iter_sections():
        if sec.name != '.text':
            continue
        base = sec.header['sh_addr']
        data = sec.data()
        for off in reversed(range(0, len(data), 2)):
            recognize(data, base, base + off, templates, recognized)
    return dict(map(tuple, map(reversed, filter(lambda (a, b): b, recognized.items()))))

if __name__ == '__main__':
    bin_path = os.path.abspath(sys.argv[1])
    ref_path = os.path.abspath(len(sys.argv) >= 3 and sys.argv[2] or "test")
    print unstrip(bin_path, ref_path)
