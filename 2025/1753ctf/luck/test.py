import hashlib
import random
import string
from itertools import product

def get_seed(input_str):
    hash_bytes = hashlib.sha256(input_str.encode()).digest()
    return int.from_bytes(hash_bytes[:4], 'little', signed=True)

def simulate(seed):
    rng = random.Random(seed)
    player = 0
    joker = 0
    while player < 100 and joker < 100:
        player += rng.randint(1, 6)
        joker += rng.randint(5, 6)
    return player > joker

# Define character set and max length
charset = string.ascii_lowercase + string.digits  # abc...z0123...
max_len = 4  # try 1–4 char strings

for length in range(1, max_len + 1):
    for chars in product(charset, repeat=length):
        seed_input = ''.join(chars)
        print("Trying:" + seed_input)
        seed = get_seed(seed_input)
        if simulate(seed):
            print(f"[+] Winning seed found: '{seed_input}'")
            exit()
