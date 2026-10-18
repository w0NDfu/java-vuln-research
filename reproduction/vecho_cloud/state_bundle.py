"""Seal a state archive for one recipient, or decrypt it on that recipient.

Only ciphertext and public metadata belong in Git. The RSA private key and
decrypted archive stay in the laboratory migration directory.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import struct

MAGIC = b"VECHO-STATE-1\n"


def crypto():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return hashes, serialization, padding, rsa, AESGCM


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def oaep(hashes, padding):
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def seal(source, recipient, destination):
    from cryptography.hazmat.backends import default_backend
    hashes, serialization, padding, rsa, AESGCM = crypto()
    public = serialization.load_pem_public_key(recipient.read_bytes(), backend=default_backend())
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 3072:
        raise ValueError("Recipient must be an RSA public key of at least 3072 bits")
    plaintext = source.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = json.dumps({
        "version": 1, "cipher": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256",
        "recipient_sha256": hashlib.sha256(der).hexdigest(),
        "wrapped_key": base64.b64encode(public.encrypt(key, oaep(hashes, padding))).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_bytes": len(plaintext),
    }, sort_keys=True, separators=(",", ":")).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    write_new(destination, MAGIC + struct.pack(">I", len(header)) + header + ciphertext)
    return {"format": "VECHO-STATE-1", "recipient_sha256": hashlib.sha256(der).hexdigest(),
            "ciphertext_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "ciphertext_bytes": destination.stat().st_size}


def unseal(source, private_key, destination):
    from cryptography.hazmat.backends import default_backend
    hashes, serialization, padding, rsa, AESGCM = crypto()
    data = source.read_bytes()
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 4:
        raise ValueError("Invalid state envelope")
    size = struct.unpack(">I", data[len(MAGIC):len(MAGIC) + 4])[0]
    start = len(MAGIC) + 4
    if not 0 < size <= 8192 or len(data) < start + size + 16:
        raise ValueError("Invalid state envelope length")
    header = data[start:start + size]
    meta = json.loads(header)
    if (meta["version"], meta["cipher"], meta["key_wrap"]) != (1, "AES-256-GCM", "RSA-OAEP-SHA256"):
        raise ValueError("Unsupported state envelope")
    private = serialization.load_pem_private_key(private_key.read_bytes(), password=None, backend=default_backend())
    if not isinstance(private, rsa.RSAPrivateKey) or private.key_size < 3072:
        raise ValueError("Invalid recipient key")
    der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if hashlib.sha256(der).hexdigest() != meta["recipient_sha256"]:
        raise ValueError("Wrong recipient")
    key = private.decrypt(base64.b64decode(meta["wrapped_key"], validate=True), oaep(hashes, padding))
    plaintext = AESGCM(key).decrypt(base64.b64decode(meta["nonce"], validate=True), data[start + size:], header)
    if len(plaintext) != meta["plaintext_bytes"] or hashlib.sha256(plaintext).hexdigest() != meta["plaintext_sha256"]:
        raise ValueError("Decrypted state checksum mismatch")
    # No file is created until authentication and checksum verification succeed.
    write_new(destination, plaintext)
    return {"verified": True, "plaintext_sha256": meta["plaintext_sha256"], "plaintext_bytes": len(plaintext)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["seal", "unseal"])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = (seal if args.operation == "seal" else unseal)(args.source, args.key, args.out)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
