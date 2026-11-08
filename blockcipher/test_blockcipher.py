import base64
import random
import os
import pytest
import blockcipher as bc

from Crypto.Cipher import DES

b64 = lambda b: base64.b64encode(b).decode()

IMG = os.path.join(os.path.dirname(__file__), "data", "kep.jpeg")

SETUPS = {
    "VIGENERE-BIN": dict(blocksize=16, key=b"hiddenkey"),
    "DES": dict(blocksize=8, key=b"12345678"),
}

def make_cfg(cipher, mode, padding="SF"):
    s = SETUPS[cipher]
    raw = dict(blocksize=s["blocksize"], cipher=cipher, key=b64(s["key"]), mode=mode, padding=padding)
    if mode != "ECB":
        raw["iv"] = b64(bytes(range(s["blocksize"])))
    return bc.parse_config(raw)

# Tesztek:

# A kep oda-vissza alakitasa kul. modszerekkel
@pytest.mark.parametrize("cipher", SETUPS)
@pytest.mark.parametrize("mode", bc.MODES)
def test_real_file_roundtrip(cipher, mode, tmp_path):
    assert os.path.getsize(IMG) >= 1_000_000
    cfg = make_cfg(cipher, mode)
    enc, out = tmp_path / "kep.enc", tmp_path / "kep.out"
    bc.encrypt_file(cfg, IMG, str(enc))
    bc.decrypt_file(cfg, str(enc), str(out))
    assert out.read_bytes() == open(IMG, "rb").read()

# Paddingek tesztelese
@pytest.mark.parametrize("padding", bc.PADDINGS)
@pytest.mark.parametrize("size", [0, 1, 7, 8, 9, 16, 17])
def test_padding_roundtrip(padding, size):
    data = bytes(range(1, size + 1))
    padded = bc.pad(data, 8, padding)
    assert len(padded) % 8 == 0
    assert bc.unpad(padded, 8, padding) == data

def test_padding_formats():
    assert bc.pad(b"abc", 8, "ZERO") == b"abc" + b"\x00" * 5
    assert bc.pad(b"abc", 8, "DES") == b"abc" + b"\x80" + b"\x00" * 4
    assert bc.pad(b"abc", 8, "SF") == b"abc" + b"\x05" * 5
    assert bc.pad(b"12345678", 8, "SF") == b"12345678" + b"\x08" * 8


# Szabvanyos-e a DES
def test_des_known_vector():
    enc, dec = bc.make_cipher("DES", bytes.fromhex("133457799BBCDFF1"), 8)
    pt = bytes.fromhex("0123456789ABCDEF")
    assert enc(pt) == bytes.fromhex("85E813540F0AB405")
    assert dec(enc(pt)) == pt
 
def test_vigenere_block():
    enc, dec = bc.make_cipher("VIGENERE-BIN", b"\x0f\xf0", 4)
    assert enc(b"\x00\x00\x00\x00") == b"\x0f\xf0\x0f\xf0"
    assert dec(enc(b"abcd")) == b"abcd"


# Megvalositott szabcanyokkal megegyeznek-e a mukodesi modok
@pytest.mark.parametrize("mode,lib", [
    ("ECB", lambda k, iv: DES.new(k, DES.MODE_ECB)),
    ("CBC", lambda k, iv: DES.new(k, DES.MODE_CBC, iv=iv)),
    ("CFB", lambda k, iv: DES.new(k, DES.MODE_CFB, iv=iv, segment_size=64)),
    ("OFB", lambda k, iv: DES.new(k, DES.MODE_OFB, iv=iv)),
])
def test_modes_match_library(mode, lib):
    cfg = make_cfg("DES", mode)
    data = random.Random(7).randbytes(100)
    expected = lib(cfg.key, cfg.iv).encrypt(bc.pad(data, 8, "SF"))
    assert bc.encrypt_bytes(cfg, data) == expected
 
 
def test_ctr_counter_increments_and_wraps():
    enc, dec = bc.make_cipher("DES", b"12345678", 8)
    cfg = bc.parse_config(dict(blocksize=8, cipher="DES", key=b64(b"12345678"),
                               mode="CTR", padding="ZERO", iv=b64(b"\xff" * 8)))
    ct = bc.encrypt_bytes(cfg, bytes(16))
    assert ct[:8] == enc(b"\xff" * 8)
    assert ct[8:] == enc(b"\x00" * 8)  
 
 
def test_example_config_loads():
    cfg = bc.load_config("config.json")
    assert (cfg.cipher, cfg.mode, cfg.padding) == ("DES", "CBC", "SF")
 
 
BASE = dict(blocksize=8, cipher="DES", key=b64(b"12345678"), mode="ECB", padding="SF")
 
 
@pytest.mark.parametrize("change", [
    dict(mode="CBC"),                                   # nincs iv
    dict(mode="CBC", iv=b64(b"short")),                 # rossz iv hossz
    dict(mode="XYZ"),
    dict(padding="PKCS"),
    dict(blocksize=16),                                 # DES csak 8 bájtos blokk
    dict(blocksize=0),
    dict(key="@@nem-base64@@"),
    dict(extra=1),                                      # additionalProperties: false
    dict(cipher="CUSTOM(student_id)"),
])
def test_invalid_configs(change):
    with pytest.raises(ValueError):
        bc.parse_config({**BASE, **change})
 
 
def test_missing_required_field():
    raw = dict(BASE)
    del raw["key"]
    with pytest.raises(ValueError):
        bc.parse_config(raw)