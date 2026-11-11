from __future__ import annotations
from typing import Callable

from Crypto.Cipher import AES, DES, DES3

BlockFn = Callable[[bytes], bytes]

CIPHERS = ("AES-128", "AES-192", "AES-256", "DES", "3DES", "VIGENERE-BIN")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")

def vigenere_bin(key: bytes, bs: int) -> tuple[BlockFn, BlockFn]:
   if not key:
       raise ValueError("VIGENRE-BIN key must not be empty")
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
    if name == "VIGENERE-BIN":
        return vigenere_bin(key, bs)
    if name in ("AES-128", "AES-192", "AES-256", "DES", "3DES"):
        return _library_cipher(name, key, bs)
    raise ValueError(f"Unsupported cipher:{name}")
