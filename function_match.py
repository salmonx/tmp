import angr
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
        self.fndict = dict()
        self.readcount = 100
        self.functions_save_path = "/tmp/{}-functions".format(os.path.basename(binary_path))
        self.fndict_save_path = "/tmp/{}-fndict".format(os.path.basename(binary_path))
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
            self.gen_fundict()
            self.find_functions()
            if self.functions:
                with open(self.functions_save_path, 'wb') as f:
                    f.write(pickle.dumps(self.functions))


    def gen_fundict(self):
        if os.path.isfile(self.fndict_save_path):
            with open(self.fndict_save_path) as f:
                self.fndict = pickle.load(f)
        if not self.fndict:
            p = angr.Project(self.binary_path, auto_load_libs=False)
            cfg = p.analyses.CFGFast()
            fndict = dict(p.kb.functions)
            nfndict = dict()

            for k in sorted(fndict.keys()):
                if not fndict[k].is_syscall:
                    nfndict[k] = fndict[k]
            with open(self.fndict_save_path,'wb') as f:
                f.write(pickle.dumps(nfndict))

            self.fndict = nfndict


    def match_function(self, addr, con):

        fns = self.libc_signs.keys()
        for fn in fns:
            sign = self.libc_signs[fn]
            if con.startswith(sign):
                return (True, fn)

        return (False, None)

    def find_functions(self):
        textsect = ELFFile(open(self.binary_path, 'rb')).get_section_by_name('.text')
        f = open(self.binary_path, 'rb')
        for addr in self.fndict.keys():
            offset = addr - textsect.header.sh_addr +  textsect.header.sh_offset
            f.seek(offset)
            con = f.read(self.readcount)
            (ret, fn) = self.match_function(addr, con)
            if ret:
                l.debug("%#x:%s", addr, fn)
                self.functions[addr] = fn


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "usage {} binary".format(sys.argv[0])
        exit(0)
    f = Functions(sys.argv[1])
    for addr, fn in f.functions.items():
        print fn, hex(addr)


