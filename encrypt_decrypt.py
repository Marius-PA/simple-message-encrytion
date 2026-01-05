from load_keys import *
from keys_generation import *
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

def encrypt(name:str, key:bytes, plaintext:str) -> dict:
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    keyname = input("Name of the ed25519 key to sign the message: ")

    #encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    a = load_ed25519(keyname)["private"]
    signature = a.sign(ciphertext)


    data = {
        "algorithm": "AES-256-GCM",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
        #"associated_data": base64.b64encode(associated_data).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signing_public_key": load_ed25519(keyname)["public_str"]
    }

    with open(f"encrypted_messages/{name}_encrypted_message.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return {"iv":iv, "ciphertext":ciphertext, "encryptor":encryptor.tag}

def decrypt(key:bytes) -> None:
    name, iv, ciphertext, tag, signature, signing_public_key, signing_public_key_str = load_ciphertext(name = input("Name of the encrypted message to retrieve: "))

    signing_public_key.verify(signature, ciphertext)

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    #decryptor.authenticate_additional_data(associated_data)

    plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext_str = plaintext_bytes.decode("utf-8")

    data = {
        "signed by": (f"{find_signer_name_locally(signing_public_key_str)}, ({signing_public_key_str})"),
        "plaintext": plaintext_str
    }

    with open(f"decrypted_messages/{name}_decrypted_message.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)