import tracer
import angr
import rex
import json
import pickle
import os

hooks = dict()
libc_start_main_addr = 0x08048F50
write =  0x806CF40
memset = 0x8048250
read =  0x0806CED0

strcpy = 0x80481C0

#hooks[libc_start_main_addr] = angr.SIM_PROCEDURES['glibc'].get('__libc_start_main')()
#hooks[libc_start_main_addr] = angr.SIM_LIBRARIES['libc.so'].get('__libc_start_main', ArchX86)
hooks[write] = angr.SIM_PROCEDURES['posix'].get('write')()
hooks[read] = angr.SIM_PROCEDURES['posix'].get('read')()
hooks[memset] = angr.SIM_PROCEDURES['libc'].get('memset')()
hooks[strcpy] = angr.SIM_PROCEDURES['libc'].get('strcpy')()


s = '0'*23 + 'aaaa' + '0'*(128-23-4)
#t = tracer.Tracer('YY_IO_BS_003_ROP', s, hooks=hooks)
#t = tracer.Tracer('YY_IO_BS_003_ROP', s)
#t = tracer.Tracer('YY_IO_BS_003_ROP', s, resiliency=False)
#t = tracer.Tracer('YY_IO_BS_003_ROP', s, hooks=hooks)
#p, st = t.run()

crash = rex.Crash('YY_IO_BS_003_ROP', s, hooks=hooks, use_rop=False, aslr=False)

print crash.crash_types
print crash.explorable()
