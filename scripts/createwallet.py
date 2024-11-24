from wallet import Wallet

def main():
    print("Membuat wallet baru dengan awalan 'sasu'...")
    wallet = Wallet(prefix="sasu")
    print(f"Wallet berhasil dibuat!")
    print(f"Address: {wallet.get_address()}")
    print(f"Public Key: {wallet.get_public_key()}")
    print(f"Private Key: {wallet.get_private_key()}")

if __name__ == "__main__":
    main()

