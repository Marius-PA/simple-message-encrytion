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

#abspath = os.path.abspath(__file__)
#dname = os.path.dirname(abspath)
#os.chdir(dname)

folder = ("private_keys", "public_keys", "encrypted_messages", "decrypted_messages")
for i in folder:
    os.makedirs(i, exist_ok=True)

# keypair generation and storage

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

    data = {
        "algorithm": "X25519",
        "name": str(name),
        "keys": {
            "private": base64.b64encode(private_bytes).decode("utf-8"),
            "public": base64.b64encode(public_bytes).decode("utf-8")
        }
    }

    with open(f"private_keys/{name}_x25519_private.json", "w") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "private_key": data["keys"]["private"]}, f, indent=2)

    with open(f"public_keys/{name}_x25519_public.json", "w") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "public_key": data["keys"]["public"]}, f, indent=2)

# derive shared secret

def derive_shared_secret(name:str, peer_public_key_bytes:bytes) -> None:
    private_key = load_x25519(name = input("Enter the name of your x25519 private key :"))["private"]
    print(private_key)
    shared_key = private_key.exchange(peer_public_key_bytes)
    # Perform key derivation.

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    data = {
        "algorithm": "AES-256-GCM",
        "name": str(name),
        "secret_shared_key": base64.b64encode(derived_key).decode("utf-8")
    }

    with open(f"private_keys/{name}_shared_key.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# load stored keys and ciphertext

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
    except FileNotFoundError:
        result["public"] = None

    return result

def load_aes_shared_key(name) -> bytes:
    with open(f"private_keys/{name}_shared_key.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return base64.b64decode(data["secret_shared_key"])

def load_ed25519(name) -> dict:
    result = {}
    try:
        with open(f"private_keys/{name}_ed25519_private.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            private_bytes = data["private_key"].encode("utf-8")
            print(private_bytes, type(private_bytes))
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
    associated_data = base64.b64decode(data["associated_data"])
    signature = base64.b64decode(data["signature"])
    signing_public_key = serialization.load_pem_public_key(public_bytes)
    signing_public_key_str = data["signing_public_key"]

    return (name, iv, ciphertext, tag, associated_data, signature, signing_public_key, signing_public_key_str)

# find signer name locally

def find_signer_name_locally(pub_key_bytes: bytes) -> str:
    # Scan your local ed25519 public keys folder
    for filename in os.listdir("public_keys"):
        if filename.endswith("_ed25519_public.json"):
            with open(f"public_keys/{filename}", "r", encoding="utf-8") as f:
                data = json.load(f)
                local_pub = data["public_key"]
                if local_pub == pub_key_bytes:
                    # Extract the name from filename or JSON
                    return data.get("name") or filename.split("_")[0]
    return "Unknown"


# Encrypt and decrypt functions

def encrypt(name:str, key:bytes, plaintext:str, associated_data:str) -> dict:
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    keyname = input("Enter the name of the ed25519 key to sign the message: ")

    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    a = load_ed25519(keyname)["private"]
    signature = a.sign(ciphertext)


    data = {
        "algorithm": "AES-256-GCM",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
        "associated_data": base64.b64encode(associated_data).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signing_public_key": load_ed25519(keyname)["public_str"]
    }

    with open(f"encrypted_messages/{name}_encrypted_message.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return {"iv":iv, "ciphertext":ciphertext, "encryptor":encryptor.tag}

def decrypt(key:bytes) -> None:
    name, iv, ciphertext, tag, associated_data, signature, signing_public_key, signing_public_key_str = load_ciphertext(name = input("Enter the name of the encrypted message to retrieve: "))

    signing_public_key.verify(signature, ciphertext)

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)

    plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext_str = plaintext_bytes.decode("utf-8")

    data = {
        "signed by": (f"{find_signer_name_locally(signing_public_key_str)}, ({signing_public_key_str})"),
        "plaintext": plaintext_str
    }

    with open(f"decrypted_messages/{name}_decrypted_message.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

#generate_ed25519_keypair(name = input("Enter a name for the ed25519 key: "))

#generate_x25519_keypair(name = input("Enter a name for the x25519 key: "))

#derive_shared_secret(
#    name = input("Enter a name for the shared secret key: "),
#    peer_public_key_bytes = load_x25519(name = input("Enter the name of the peer's x25519 public key: "))["public"]
#)

#encrypt(
#    name = input("Enter a name for the encrypted message: "),
#    key = load_aes_shared_key(name = input("Enter the name of the AES shared key for encryption: ")),
#    plaintext = input("Enter a message to encrypt: ").encode("utf-8"),
#    associated_data = b"authenticated but not encrypted payload"
#)
decrypt(
    key = load_aes_shared_key(name = input("Enter the name of the AES key to use for decryption: ")),
)
