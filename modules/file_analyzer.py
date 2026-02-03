import hashlib
import math
import os
import base64
from urllib.parse import urlparse
from cryptography.fernet import Fernet

def compute_hashes(path: str) -> dict:
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            for h in hashes.values():
                h.update(chunk)

    return {name: h.hexdigest() for name, h in hashes.items()}


def calculate_entropy(path: str) -> float:
    byte_counts = [0] * 256
    total = 0

    with open(path, "rb") as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            total += len(data)
            for b in data:
                byte_counts[b] += 1

    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def detect_packing(path: str) -> str:
    entropy = calculate_entropy(path)
    if entropy >= 7.5:
        return f"High entropy ({entropy:.2f}) – possibly packed"
    elif entropy >= 6.5:
        return f"Moderate entropy ({entropy:.2f}) – maybe compressed"
    else:
        return f"Low entropy ({entropy:.2f}) – likely not packed"

def analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    scheme = parsed.scheme or "http"

    suspicious = False
    reasons = []

    if scheme != "https":
        suspicious = True
        reasons.append("Not using HTTPS")

    if len(domain) > 40:
        suspicious = True
        reasons.append("Domain too long")

    bad_words = ["login", "verify", "secure", "update", "free"]
    if any(w in domain.lower() for w in bad_words):
        suspicious = True
        reasons.append("Suspicious keyword found")

    return {
        "url": url,
        "domain": domain,
        "scheme": scheme,
        "is_https": scheme == "https",
        "suspicious": suspicious,
        "reasons": reasons,
    }
def _generate_key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_file(path: str, password: str) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    key = _generate_key(password)
    fernet = Fernet(key)

    with open(path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    out_path = path + ".enc"

    with open(out_path, "wb") as f:
        f.write(encrypted)

    return out_path


def decrypt_file(path: str, password: str) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError("Encrypted file not found")

    if not path.endswith(".enc"):
        raise ValueError("Selected file is not a .enc encrypted file")
    
    key = _generate_key(password)
    fernet = Fernet(key)

    try:
        with open(path, "rb") as f:
            data = f.read()

        decrypted = fernet.decrypt(data)

    except Exception:
        raise ValueError("Decryption failed: Wrong password or corrupted file")

    out_path = path[:-4]  # removes .enc

    with open(out_path, "wb") as f:
        f.write(decrypted)

    return out_path
