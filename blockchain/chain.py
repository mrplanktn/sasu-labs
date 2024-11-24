import time
from block import Block

class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions = []

    def create_genesis_block(self):
        return Block(0, "0", time.time(), "Genesis Block")

    def get_latest_block(self):
        return self.chain[-1]

    def mine_block(self, miner_public_key):
        data = {
            "transactions": self.pending_transactions,
            "miner": miner_public_key
        }
        new_block = Block(len(self.chain), self.get_latest_block().hash, time.time(), data)
        # Proof of Work (POW)
        while not new_block.hash.startswith("0" * self.difficulty):
            new_block.nonce += 1
            new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)
        self.pending_transactions = []
        return new_block

    def create_transaction(self, sender, recipient, amount):
        transaction = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount
        }
        self.pending_transactions.append(transaction)
        return "Transaction added!"
