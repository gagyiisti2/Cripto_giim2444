# importok
from __future__ import annotations

import json
import base64
import argparse
import binascii

from dataclasses import dataclass 
from typing import Callable, Optional

import paddings as p
import ciphers as cip
import processmodes as mod

BlockFn = Callable[[bytes], bytes]

# konfiguracio

_REQUIRED = ("blocksize","cipher","key","mode","padding")
_ALLOWED  = _REQUIRED + ("iv",)

@dataclass(frozen=True)
class CipherConfig: 
    blocksize: int
    cipher: str
    key: bytes
    mode: str
    padding: str
    iv: Optional[bytes] = None

def _b64(value, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"{field} is not valid base64") from e

def parse_config(raw: dict) -> CipherConfig:
    if not isinstance(raw, dict):
        raise ValueError("config must be a JSON object")
    extra = set(raw) - set(_ALLOWED)
    if extra:
        raise ValueError(f"unknown config field(s): {sorted(extra)}")
    missing = [k for k in _REQUIRED if k not in raw]
    if missing:
        raise ValueError(f"missing config field(s): {sorted(missing)}")

    bs = raw["blocksize"]
    if isinstance(bs, bool) or not isinstance(bs, int) or not 1 <= bs <= 64:
        raise ValueError(f"{bs} must be an intiger between 1 and 64")
    for field, allowed in (("cipher", cip.CIPHERS), ("mode", mod.MODES), ("padding", p.PADDINGS)):
        if raw[field] not in allowed:
            raise ValueError(f"'{field}' must be one of {list(allowed)}")

    key = _b64(raw["key"], "key")
    iv = _b64(raw["iv"], "iv") if "iv" in raw else None
    if raw["mode"] != "ECB":
        if iv is None:
            raise ValueError(f"'iv' is required in mode {raw['mode']}")
        if len(iv) != bs:
            raise ValueError(f"'iv' must be exactly {bs} bytes, got {len(iv)}")
    cfg = CipherConfig(bs, raw["cipher"], key, raw["mode"], raw["padding"], iv)
    cip.make_cipher(cfg.cipher, cfg.key, cfg.blocksize)
    return cfg

def load_config(path: str) -> CipherConfig:
    with open(path, "r", encoding="utf-8") as f:
        return parse_config(json.load(f))

# Belepesi fuggvenyek

def encrypt_bytes(cfg: CipherConfig, data: bytes) -> bytes:
    enc, dec = cip.make_cipher(cfg.cipher, cfg.key, cfg.blocksize)
    padded = p.pad(data, cfg.blocksize, cfg.padding)
    return mod.process_mode(cfg.mode, padded, cfg.blocksize, enc, dec, cfg.iv, True)

def decrypt_bytes(cfg: CipherConfig, data: bytes) -> bytes:
    enc, dec = cip.make_cipher(cfg.cipher, cfg.key, cfg.blocksize)
    plain = mod.process_mode(cfg.mode, data, cfg.blocksize, enc, dec, cfg.iv, False)
    return p.unpad(plain, cfg.blocksize, cfg.padding)

def encrypt_file(cfg: CipherConfig, src: str, dst: str) -> None:
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(encrypt_bytes(cfg, data))
 
def decrypt_file(cfg: CipherConfig, src: str, dst: str) -> None:
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(decrypt_bytes(cfg, data))

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Block cipher driven by JSON configuration")
    p.add_argument("action", choices=("encrypt", "decrypt"))
    p.add_argument("config")
    p.add_argument("input")
    p.add_argument("output")
    args = p.parse_args(argv)
    cfg = load_config(args.config)
    (encrypt_file if args.action == "encrypt" else decrypt_file)(cfg, args.input, args.output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())