import sys
import os
import cPickle as pickle
from elftools.elf.elffile import ELFFile
import signlibc
import re
import logging

l = logging.getLogger("functions")
langr = logging.getLogger("angr")

langr.setLevel(logging.WARNING)
l.setLevel(logging.DEBUG)


class Functions():

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.functions = dict()
        self.functions_save_path = "/tmp/{}-functions".format(os.path.basename(binary_path))
        self.libc_signs = dict()

        self.get_libc_signs()
        self.get_functions()

    def get_libc_signs(self):
        clibc = signlibc.LibcSign()
        self.libc_signs = clibc.signs

    def get_functions(self):
        if os.path.isfile(self.functions_save_path):
            with open(self.functions_save_path, 'rb') as f:
                self.functions = pickle.load(f)
        else:
            self.find_functions()
            if self.functions:
                with open(self.functions_save_path, 'wb') as f:
                    f.write(pickle.dumps(self.functions))


    def find_functions(self):
        textsect = ELFFile(open(self.binary_path, 'rb')).get_section_by_name('.text')
        fcon = open(self.binary_path, 'rb').read()

        for fn in self.libc_signs.keys():
            sign = self.libc_signs[fn]
            try:
                index = fcon.index(sign)
                addr = index + textsect.header.sh_addr -  textsect.header.sh_offset
                l.debug("%#x:%s", addr, fn)
                self.functions[addr] = fn
            except:
                pass


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "usage {} binary".format(sys.argv[0])
        exit(0)
    f = Functions(sys.argv[1])
    for addr, fn in f.functions.items():
        print fn, hex(addr)



