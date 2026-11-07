# importok
from __future__ import annotations

import json
import base64
import argparse
import binascii
from dataclasses import dataclass 
from typing import Callable, Optional

BlockFn = Callable[[bytes], bytes]


# globalis valtozok
MODES = ("ECB", "CBC", "CFB", "OFB", "CTR")
PADDINGS = ("ZERO", "DES", "SF")
CIPHERS = ("AES-128", "AES-192", "AES-256", "DES", "3DES", "VIGENERE-BIN")

# 1. paddingek
def pad(data: bytes, bs: int, scheme: str) -> bytes:
    n = bs - (len(data) % bs)
    
    if scheme == "ZERO":
        return data + b"\x00" * (n % bs) # ha a hataron lenne ne tegyunk hozza meg egy blokkot
    
    if scheme == "DES":
        return data + b"\x80" + b"\x00" * (n - 1) 
    
    if scheme == "SF":
        return data + bytes([n]) * n
    
    raise ValueError(f"Unknown padding: {scheme}")

def unpad(data: bytes, bs: int, scheme: str) -> bytes:
    if scheme == "ZERO":
        return data.rstrip(b"\x00")
    
    if scheme == "DES":
        stripped = data.rstrip(b"\x00")
        if not stripped.endswith(b"\x80"):
            raise ValueError("Invalid DES padding")
        return stripped[:-1]
    
    if scheme == "SF":
        if not data:
            raise ValueError("Invalid SF padding")
        n = data[-1]
        if n < 1 or n > bs or data[-n:] != bytes([n]) * n:
            raise ValueError("Invalid SF padding")
        return data[:-n]
    raise ValueError(f"Unknown padding: {scheme}")

# 2. titkositok
from Crypto.Cipher import AES, DES, DES3

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")

def vinegre_bin(key: bytes, bs: int) -> tuple[BlockFn, BlockFn]:
   if not key:
       raise ValueError("VINEGRE-BIN key must not be empty")
   keystream = (key * (bs // len(key) + 1))[:bs] # feltoltunk egy blokk hosszusagot a kulcs ismetlesevel
   def crypt(block: bytes) -> bytes:
        return xor_bytes(block, keystream) 
   return crypt, crypt

def _library_cipher(name: str, key: bytes, bs: int) -> tuple[BlockFn, BlockFn]:

    table = {
        "DES":(DES, 8, (8,)),
        "3DES":(DES3, 8, (16,24)),
        "AES-128": (AES, 16, (16,)),
        "AES-192": (AES, 16, (24,)),
        "AES-256": (AES, 16, (32,)),
    }

    module, block_size, key_sizes = table[name]

    if bs != block_size:
        raise ValueError(f"{name} requires blocksize={block_size}, got {bs}")
    if len(key) not in key_sizes:
        raise ValueError(f"{name} key must be {' or '.join(map(str, key_sizes))} bytes, got {len(key)}")
    
    ecb = module.new(key, module.MODE_ECB)
    return ecb.encrypt, ecb.decrypt

def make_cipher(name: str, key: bytes, bs: int) -> tuple[BlockFn, BlockFn]:
    if name == "VINEGERE-BIN":
        return vinegre_bin(key, bs)
    if name in ("AES-128", "AES-192", "AES-256", "DES", "3DES"):
        return _library_cipher(name, key, bs)
    raise ValueError(f"Unsupported cipher{name}")

# 3. mukodesi modok
def process_mode(mode: str, data: bytes, bs: int, enc: BlockFn, dec: BlockFn,
                 iv: Optional[bytes], encrypting: bool) -> bytes:
    if len(data) % bs > 0:
        raise ValueError("Data length must be multiple of the block size")
    blocks = [data[i:i + bs] for i in range(0, len(data), bs)]
    out = list[bytes] = []

    if mode == "ECB":
        f = enc if encrypting else dec
        out = [f(b) for b in blocks]

    elif mode == "CBC":
        prev = iv
        for b in blocks:
            if encrypting:
                prev = enc(xor_bytes(b, prev))
                out.append(prev)
            else:
                out.append(xor_bytes(dec(b), prev))
                prev = b
    
    elif mode == "CFB":
        prev = iv
        for b in blocks:
            c = xor_bytes(enc(prev), b)
            out.append(c)
            prev = c if encrypting else b
    
    elif mode == "OFB":
        o = iv
        for b in blocks:
            o = enc(o)
            out.append(xor_bytes(b, o))

    elif mode == "CTR":
        n = int.from_bytes(iv, "big")
        mod = 1 << (8 * bs)
        for i, b in enumerate(blocks):
            out.append(xor_bytes(b, enc(((n + i) % mod).to_bytes(bs, "big"))))
    else:
        raise ValueError(f"unkown mode {mode}")
    return b"".join(out)

# 4. konfiguracio
