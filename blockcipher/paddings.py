PADDINGS = ("ZERO", "DES", "SF")

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