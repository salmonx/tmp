import os
from elftools.elf.elffile import ELFFile
import re
import cPickle as pickle

l = 30
sign_fn = '/tmp/sign_libc'

class libcsign():

    def __init__(self):
        self.signs = self.get_sign()


    def gen_sign(self, f):
        fn = os.path.basename(f).split('.o')[0]
        section = ELFFile(open(f, 'rb')).get_section_by_name('.text')
        con = section.data()
         
        # syscall
        call = "(.*?)\xb8(?P<eax>.{2})\x00\x00\xff\x15(.){4}"
        m = re.match(call, con)
        if m:
            con = m.group(0)
        else:
            con = con[ : min(len(con), l)]
        return fn, con


    def get_sign(self):
        if not os.path.isfile(sign_fn):

            t = dict()
            f = os.listdir('./libc')
            for ff in f:
                p = os.path.join(os.path.abspath('./libc'), ff)
                fn, con = self.gen_sign(p)
                if len(con) > 0:
                    t[fn] = con

            with open(sign_fn, 'w') as f:
                f.write(pickle.dumps(t))
            return t
 
        else:
            return pickle.load(open(sign_fn, 'rb'))



c = libcsign()
print c.signs 
