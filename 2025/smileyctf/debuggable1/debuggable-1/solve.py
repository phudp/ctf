from pwn import *
import base64
# nc smiley.cat 43637
# Update these:
HOST = 'smiley.cat'
PORT = 41081
BINARY_PATH = './fake.elf'  # Your compiled ELF path

# Connect to remote
io = remote(HOST, PORT)

# Read ELF and base64-encode it
with open(BINARY_PATH, 'rb') as f:
    elf_data = f.read()

b64_data = base64.b64encode(elf_data).decode()  # Convert to str

# Wait for prompt (customize based on actual input prompt)
io.recvuntil(b"elf:")

# Send base64 data
io.sendline(b64_data)

# Receive response
output = io.recvall(timeout=5).decode(errors='ignore')
print(output)
