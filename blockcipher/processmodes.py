from __future__ import annotations
import ciphers as cip
from typing import Callable, Optional

BlockFn = Callable[[bytes], bytes]

MODES = ("ECB", "CBC", "CFB", "OFB", "CTR")

def process_mode(mode: str, data: bytes, bs: int, enc: BlockFn, dec: BlockFn,
                 iv: Optional[bytes], encrypting: bool) -> bytes:
    if len(data) % bs > 0:
        raise ValueError("Data length must be multiple of the block size")
    blocks = [data[i:i + bs] for i in range(0, len(data), bs)]
    out: list[bytes] = []

    if mode == "ECB":
        f = enc if encrypting else dec
        out = [f(b) for b in blocks]

    elif mode == "CBC":
        prev = iv
        for b in blocks:
            if encrypting:
                prev = enc(cip.xor_bytes(b, prev))
                out.append(prev)
            else:
                out.append(cip.xor_bytes(dec(b), prev))
                prev = b
    
    elif mode == "CFB":
        prev = iv
        for b in blocks:
            c = cip.xor_bytes(enc(prev), b)
            out.append(c)
            prev = c if encrypting else b
    
    elif mode == "OFB":
        o = iv
        for b in blocks:
            o = enc(o)
            out.append(cip.xor_bytes(b, o))

    elif mode == "CTR":
        n = int.from_bytes(iv, "big")
        mod = 1 << (8 * bs)
        for i, b in enumerate(blocks):
            out.append(cip.xor_bytes(b, enc(((n + i) % mod).to_bytes(bs, "big"))))
    else:
        raise ValueError(f"unknown mode {mode}")
    return b"".join(out)