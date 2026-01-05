from load_keys import *
from unittest import result
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import os, json, base64
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ed25519_keypair(name) -> None:

    # --- PRIVATE KEY (raw bytes) ---
    private_key = Ed25519PrivateKey.generate()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # --- PUBLIC KEY (PEM, text-safe) ---
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    data = {
        "algorithm": "ed25519",
        "name": str(name),
        "keys": {
            "private": private_bytes.decode("utf-8"),
            "public": public_bytes.decode("utf-8")
        }
    }

    with open(f"private_keys/{name}_ed25519_private.json", "w", encoding="utf-8") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "private_key": data["keys"]["private"]}, f, indent=2)

    with open(f"public_keys/{name}_ed25519_public.json", "w", encoding="utf-8") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "public_key": data["keys"]["public"]}, f, indent=2)

def generate_x25519_keypair(name) -> None:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    signer_name = input("Name of the ed25519 private key to sign the x25519 public key: ")
    ed_priv = load_ed25519(signer_name)["private"]
    
    signature = ed_priv.sign(public_bytes)
    
    data = {
        "algorithm": "X25519",
        "name": str(name),
        "signing_public_key": load_ed25519(signer_name)["public_str"],
        "signature": base64.b64encode(signature).decode("utf-8"),
        "keys": {
            "private": base64.b64encode(private_bytes).decode("utf-8"),
            "public": base64.b64encode(public_bytes).decode("utf-8")
        }
    }

    with open(f"private_keys/{name}_x25519_private.json", "w") as f:
        json.dump({"algorithm": data["algorithm"],
                   "name": data["name"],
                   "private_key": data["keys"]["private"]},
                  f, indent=2)

    with open(f"public_keys/{name}_x25519_public.json", "w") as f:
        json.dump({"algorithm": data["algorithm"],
                   "name": data["name"],
                   "signing_public_key": data["signing_public_key"],
                   "signature": data["signature"],
                   "public_key": data["keys"]["public"]},
                  f, indent=2)

# derive shared secret

def derive_shared_secret(name:str, peer_public_key_bytes:bytes) -> None:
    x25519name = input("[derived key] x25519 profile key private/public must be same name: ")
    signature = load_x25519(name = x25519name)["signature"]
    private_key = load_x25519(name = x25519name)["private"]
    loaded_public_key = load_ed25519(name = input("ed25519 public key to verify the peer x25519 public"))["public"]
    print(loaded_public_key, type(loaded_public_key))
    #loaded_public_key =  base64.b64decode(loaded_public_key)
    shared_key = private_key.exchange(peer_public_key_bytes)
    
    public_bytes = data["signing_public_key"].encode("utf-8")

    signature = base64.b64decode(load_x25519(name = x25519name)["signature"])
    signing_public_key = serialization.load_pem_public_key(public_bytes)
    signing_public_key_str = data["signing_public_key"]
    
    signing_public_key.verify(signature, loaded_public_key)
    
    # Perform key derivation.

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        #info=b'handshake data',
    ).derive(shared_key)

    data = {
        "algorithm": "AES-256-GCM",
        "name": str(name),
        "signer": x25519name,
        "secret_shared_key": base64.b64encode(derived_key).decode("utf-8")
    }

    with open(f"private_keys/{name}_shared_key.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)