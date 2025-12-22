from unittest import result
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519
import os, json, base64
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#abspath = os.path.abspath(__file__)
#dname = os.path.dirname(abspath)
#os.chdir(dname)

# keypair generation and storage

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

    with open(f"{name}_x25519_private.json", "w") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "private_key": data["keys"]["private"]}, f, indent=2)

    with open(f"{name}_x25519_public.json", "w") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "public_key": data["keys"]["public"]}, f, indent=2)
#generate_x25519_keypair(name = input("Enter a name for the x25519 key: "))

def generate_aes_key(name) -> None:
    data = {
        "algorithm": "AES-256-GCM",
        "name": str(name),
        "key": base64.b64encode(os.urandom(32)).decode("utf-8"),
        "iv": base64.b64encode(os.urandom(16)).decode("utf-8") 
    }

    with open(f"{name}_aes256gcm_key.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
#generate_aes_key(name = input("Enter a name for the AES key: "))

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
            "private": base64.b64encode(private_bytes).decode("utf-8"),
            "public": base64.b64encode(public_bytes).decode("utf-8")
        }
    }

    with open(f"{name}_ed25519_private.json", "w", encoding="utf-8") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "private_key": data["keys"]["private"]}, f, indent=2)

    with open(f"{name}_ed25519_public.json", "w", encoding="utf-8") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "public_key": data["keys"]["public"]}, f, indent=2)
#generate_ed25519_keypair(name = input("Enter a name for the ed25519 key: "))

def load_x25519(name) -> dict:
    result = {}
    try:
        with open(f"{name}_x25519_private.json") as f:
            data = json.load(f)
            result["private"] = base64.b64decode(data["private"])
    except FileNotFoundError:
        result["private"] = None

    try:
        with open(f"{name}_x25519_public.json") as f:
            pub_data = json.load(f)
            result["public"] = base64.b64decode(pub_data["public"])
    except FileNotFoundError:
        result["public"] = None

    return result

def load_ed25519(name) -> dict:
    result = {}
    try:
        with open(f"{name}_ed25519_private.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            result["private"] = data["private_key"]
    except FileNotFoundError:
        result["private"] = None
    try:
        with open(f"{name}_ed25519_public.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            result["public"] = data["public_key"]
    except FileNotFoundError:
        result["public"] = None

    return result

# derive shared secret

def derive_shared_secret(name:str, peer_public_key_bytes:bytes) -> None:
    get_private_key = load_x25519(name = input("Enter the name of your x25519 private key :"))
    private_key = get_private_key["private"]
    peer_public_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    # Perform key derivation.

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    with open(f"{name}_shared_key.json", "w", encoding="utf-8") as f:
        json.dump({"derived_key": base64.b64encode(derived_key).decode("utf-8")}, f, indent=2)


# load stored keys and ciphertext

def load_aes_key(name) -> bytes:
    with open(f"{name}_aes256gcm_key.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return base64.b64decode(data["key"])

def load_ciphertext(name, only_ciphertext=False):
    with open(f"{name}_encrypted_message.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    tag = base64.b64decode(data["tag"])
    associated_data = base64.b64decode(data["associated_data"])

    if only_ciphertext:
        return ciphertext

    return (iv, ciphertext, tag, associated_data)

# Encrypt and decrypt functions

def encrypt(name:str, key:bytes, plaintext:str, associated_data:str):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    keyname = input("Enter the name of the ed25519 key to sign the message: ")

    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    signature = load_ed25519(keyname)["private"].sign(ciphertext)
    print("Signature:", base64.b64encode(signature).decode("utf-8"))

    data = {
        "algorithm": "AES-256-GCM",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
        "associated_data": base64.b64encode(associated_data).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
        "singing_public_key": base64.b64encode(load_ed25519(keyname)["public"]).decode("utf-8")
    }

    with open(f"{name}_encrypted_message.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return {"iv":iv, "ciphertext":ciphertext, "encryptor":encryptor.tag}

def decrypt(key:bytes):
    iv, ciphertext, tag, associated_data = load_ciphertext(name = input("Enter the name of the encrypted message to retrieve: "), only_ciphertext=False)

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)

    plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext_str = plaintext_bytes.decode("utf-8")

    return plaintext_str




#encrypt(
    name = input("Enter a name for the encrypted message: "),
    key = retrieve_aes_key(name = input("Enter the name of the AES key to use for encryption: ")),
    plaintext = b"a secret message!",
    associated_data = b"authenticated but not encrypted payload"
#)


#print(decrypt(
    key = retrieve_aes_key(name = input("Enter the name of the AES key to use for decryption: ")),
#))
