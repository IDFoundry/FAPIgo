"""Independent reference for FAPIgo's pairwise.NewHMAC (and NewHMACWith).

HMAC-SHA-256 with Python's stdlib hmac/hashlib, over the domain label
and the issuer, sector and subject, each prefixed with its length as a
4-byte big-endian integer; the body is the unpadded base64url encoding.
Prints pairwise/testdata/hmac_vectors.json.
"""
import base64, hashlib, hmac, json, struct

DOMAIN = b"fapigo ppid h1"

def lp(field: bytes) -> bytes:
    return struct.pack(">I", len(field)) + field

def derive(key: bytes, issuer: str, sector: str, subject: str) -> str:
    data = lp(DOMAIN) + lp(issuer.encode()) + lp(sector.encode()) + lp(subject.encode())
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()

KEY = bytes(range(0, 32))
OTHER_KEY = bytes((3 + 7 * i) % 256 for i in range(32))
OP = "https://op.example"
RP = "rp.example"

CASES = [
    (KEY, OP, RP, "user-1"),
    (KEY, OP, RP, "user-2"),
    (KEY, OP, "other.example", "user-1"),
    (KEY, "https://other-op.example", RP, "user-1"),
    (OTHER_KEY, OP, RP, "user-1"),
    (KEY, "https://op.example/tenant/a", "app.example.com", "alice@example.com"),
    (KEY, OP, RP, "x" * 255),
    (KEY, OP, RP, "a b ~!"),
]

print(json.dumps({
    "construction": "HMAC-SHA-256(key, u32be(len(f)) || f for f in [\"fapigo ppid h1\", issuer, sector, subject]), base64url without padding",
    "vectors": [
        {"key": k.hex(), "issuer": i, "sector": s, "subject": sub, "body": derive(k, i, s, sub)}
        for k, i, s, sub in CASES
    ],
}, indent=2))
