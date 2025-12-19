from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import os, json, base64
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def generate_ed25519_keypair(name):

    # --- PRIVATE KEY (raw bytes) ---
    private_key = ed25519.Ed25519PrivateKey.generate()

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

    with open(f"{name}_ed25519.private", "w", encoding="utf-8") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "private_key": data["keys"]["private"]}, f, indent=2)

    with open(f"{name}_ed25519.public", "w", encoding="utf-8") as f:
        json.dump({"algorithm": data["algorithm"], "name": data["name"], "public_key": data["keys"]["public"]}, f, indent=2)
#generate_ed25519_keypair(name = input("Enter a name for the key: "))

def generate_aes_key(name):
    data = {
        "algorithm": "AES-256-GCM",
        "name": str(name),
        "key": os.urandom(32).hex(),
        "iv": os.urandom(16).hex()
    }

    with open(f"{name}_aes256gcm.key", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
#generate_aes_key(name = input("Enter a name for the AES key: "))

def retrieve_aes_key(name):
    with open(f"{name}_aes256gcm.key", "r", encoding="utf-8") as f:
        data = json.load(f)
    return bytes.fromhex(data["key"])

def retrieve_ed25519_private_key(name):
    with open(f"{name}_ed25519.private", "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["private_key"]

def retrieve_ed25519_public_key(name):
    with open(f"{name}_ed25519.public", "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["public_key"]

def retrieve_ciphertext(name):
    with open(f"{name}_aes256gcm.encrypted", "r", encoding="utf-8") as f:
        data = json.load(f)

    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    tag = base64.b64decode(data["tag"])
    associated_data = base64.b64decode(data["associated_data"])

    return (iv, ciphertext, tag, associated_data)

def encrypt(name ,key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    data = {
        "algorithm": "AES-256-GCM",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
        "associated_data": base64.b64encode(associated_data).decode("utf-8")
    }

    with open(f"{name}_aes256gcm.aes", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return (iv, ciphertext, encryptor.tag)

def decrypt(filename ,key, associated_data, iv, ciphertext, tag):

    with open(f"{filename}_.encrypted", "r", encoding="utf-8") as f:
        data = json.load(f)

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


#iv, ciphertext, tag = encrypt(
    name = input("Enter a name for the encrypted message: "),
    key = retrieve_aes_key(name = input("Enter the name of the AES key to use for encryption: ")),
    plaintext = b"a secret message!",
    associated_data = b"authenticated but not encrypted payload"
#)

iv, ciphertext, tag, associated_data = retrieve_ciphertext(
    name = input("Enter the name of the encrypted message to retrieve: ")
)

print(decrypt(
    filename = input("Enter the name of the encrypted message to decrypt: "),
    key = retrieve_aes_key(name = input("Enter the name of the AES key to use for decryption: ")),
    associated_data = associated_data,
    iv = iv,
    ciphertext = ciphertext,
    tag = tag
))
