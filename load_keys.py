from cryptography.hazmat.primitives import serialization
import json, base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# load stored keys and ciphertext

def load_aes_shared_key(name) -> bytes:
    with open(f"private_keys/{name}_shared_key.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return base64.b64decode(data["secret_shared_key"])

def load_x25519(name) -> dict:
    result = {}
    try:
        with open(f"private_keys/{name}_x25519_private.json") as f:
            data = json.load(f)
            result["private"] = X25519PrivateKey.from_private_bytes(base64.b64decode(data["private_key"]))
    except FileNotFoundError:
        result["private"] = None

    try:
        with open(f"public_keys/{name}_x25519_public.json") as f:
            data = json.load(f)
            result["public"] = X25519PublicKey.from_public_bytes(base64.b64decode(data["public_key"]))
            result["signature"] = base64.b64decode(data["signature"])
            result["signing_public_key_str"] = data["signing_public_key"]
    except FileNotFoundError:
        result["public"] = None

    return result

def load_ed25519(name) -> dict:
    result = {}
    try:
        with open(f"private_keys/{name}_ed25519_private.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            private_bytes = data["private_key"].encode("utf-8")
            result["private"] = serialization.load_pem_private_key(
                private_bytes,
                password=None
            )
            result["private_str"] = data["private_key"]
    except FileNotFoundError:
        result["private"] = None
    try:
        with open(f"public_keys/{name}_ed25519_public.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            public_bytes = data["public_key"].encode("utf-8")
            result["public"] = serialization.load_pem_public_key(public_bytes)
            result["public_str"] = data["public_key"]
    except FileNotFoundError:
        result["public"] = None

    return result

def load_ciphertext(name) -> tuple:

    with open(f"encrypted_messages/{name}_encrypted_message.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    public_bytes = data["signing_public_key"].encode("utf-8")

    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    tag = base64.b64decode(data["tag"])
    #associated_data = base64.b64decode(data["associated_data"])
    signature = base64.b64decode(data["signature"])
    signing_public_key = serialization.load_pem_public_key(public_bytes)
    signing_public_key_str = data["signing_public_key"]

    return (name, iv, ciphertext, tag, signature, signing_public_key, signing_public_key_str)