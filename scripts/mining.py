from blockchain import Blockchain
from wallet import Wallet

def main():
    blockchain = Blockchain(difficulty=4)
    wallet = Wallet(prefix="sasu")
    print("Menambang blok baru...")
    block = blockchain.mine_block(wallet.get_public_key())
    print(f"Block berhasil ditambang: {block.hash}")

if __name__ == "__main__":
    main()
