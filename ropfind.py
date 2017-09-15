import angr
import angrop
import sys
import hashlib
import os


binary = sys.argv[1]

project = angr.Project(binary)

# we search for ROP gadgets now to avoid the memory exhaustion bug in pypy
# hash binary contents for rop cache name
binhash = hashlib.md5(open(binary).read()).hexdigest()
rop_cache_path = os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(binary), binhash))


if not os.path.exists(rop_cache_path):
    rop = project.analyses.ROP()
    rop.find_gadgets(show_progress=False)
    rop.save_gadgets(rop_cache_path)
