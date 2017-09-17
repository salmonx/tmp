import sys


def find_jmpesp(binary):
    from elftools.elf.elffile import ELFFile
    data = open(binary, 'rb').read()
    jmpesp = "\xff\xe4" 
    if jmpesp in data:
        index = data.index(jmpesp)

    lastsec = None
    for sec in ELFFile(open(binary, 'rb')).iter_sections():
        if index > sec.header.sh_offset:
            lastsec = sec
        else:
            addr = lastsec.header.sh_addr + index - lastsec.header.sh_offset
            return addr
    return False




if __name__ == '__main__':
    addr = find_jmpesp(sys.argv[1])
    print "addr:", hex(addr)
