from encrypt import *

while True:
    choose_action = input("\nChoose an action: \n1. Generate ed25519 keypair\n2. Generate x25519 keypair\n3. Derive shared secret\n4. Encrypt message\n5. Decrypt message\n6. Exit\n\n[!] Choice: ")

    if choose_action == "1":
        try:
            generate_ed25519_keypair(name = input("Enter a name for the ed25519 key: "))
            print("[+] Key generation successful ✅")
        except Exception as e:
            print(f"Error generating ed25519 keypair: {e}")
    
    if choose_action == "2":
        try:
            generate_x25519_keypair(name = input("Enter a name for the x25519 key: "))
            print("[+] Key generation successful ✅")
        except Exception as e:
            print(f"Error generating x25519 keypair: {e}")
    
    if choose_action == "3":
        try:
            derive_shared_secret(
                name = input("Enter a name for the shared secret key: "),
                peer_public_key_bytes = load_x25519(name = input("Enter the name of the peer's x25519 public key: "))["public"]
            )
            print("[+] Key derived successful ✅")
        except Exception as e:
            print(f"Error deriving shared secret: {e}")
            print("Please ensure the peer's public key exists.")

    if choose_action == "4":
        try:
            encrypt(
                name = input("Enter a name for the encrypted message: "),
                key = load_aes_shared_key(name = input("Enter the name of the AES shared key for encryption: ")),
                plaintext = input("Enter a message to encrypt: ").encode("utf-8"),
                #associated_data = b"authenticated but not encrypted payload"
            )
            print("[+] Encryption successful  ✅")
        except Exception as e:
            print("[-] Encryption failed ❌")
            print(f"Error encrypting message: {e}")

    if choose_action == "5":
        try:
            decrypt(
                key = load_aes_shared_key(name = input("Enter the name of the AES key to use for decryption: "))
            )
            print("[+] Decryption successful  ✅")
        except Exception as e:
            print("[-] Decryption failed ❌")
            print(f"Error decrypting message: {e}")
    
    if choose_action == "6":
        print("[+] Bye")
        break
