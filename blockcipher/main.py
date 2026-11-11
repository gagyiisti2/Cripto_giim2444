from __future__ import annotations

from dataclasses import dataclass 
from typing import Callable, Optional

import paddings as p
import ciphers as cip
import processmodes as mod
import blockcipher as bc

def main(argv: Optional[list[str]] = None) -> int:
    p = bc.argparse.ArgumentParser(description="Block cipher driven by JSON configuration")
    p.add_argument("action", choices=("encrypt", "decrypt"))
    p.add_argument("config")
    p.add_argument("input")
    p.add_argument("output")
    args = p.parse_args(argv)
    cfg = bc.load_config(args.config)
    (bc.encrypt_file if args.action == "encrypt" else bc.decrypt_file)(cfg, args.input, args.output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())