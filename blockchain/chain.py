import hashlib
import json
import time
import random
import threading
from queue import Queue
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.difficulty = 4  # Default proof-of-work difficulty
        self.validators = {}  # Staking pool for PoS
        self.queue = Queue()  # Transaction queue for parallel processing
        self.transaction_pool = []  # Pool of unconfirmed transactions
        self.new_block(previous_hash='1', proof=100)  # Genesis block
        self.validator_lock = threading.Lock()  # To ensure only one validator updates the chain at a time

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': self.generate_proof_of_history(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        transaction = {'sender': sender, 'recipient': recipient, 'amount': amount}
        self.transaction_pool.append(transaction)  # Add transaction to pool
        return self.last_block['index'] + 1

    def process_transactions(self):
        """Process transactions in parallel."""
        while True:
            if len(self.transaction_pool) > 0:
                transaction = self.transaction_pool.pop(0)
                self.current_transactions.append(transaction)

    def hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def generate_proof_of_history(self):
        """Create a deterministic timestamp using hash chaining."""
        return hashlib.sha256(f"{time.time()}".encode()).hexdigest()

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == "0" * self.difficulty

    def stake(self, validator_address, amount):
        """Add stake to a validator."""
        with self.validator_lock:  # Ensure thread-safe stake updates
            if validator_address not in self.validators:
                self.validators[validator_address] = 0
            self.validators[validator_address] += amount

    def select_validator(self):
        """Randomly select a validator based on stake weight."""
        total_stake = sum(self.validators.values())
        pick = random.uniform(0, total_stake)
        current = 0
        for validator, stake in self.validators.items():
            current += stake
            if current > pick:
                return validator

    def generate_keys(self):
        """Generate a private-public key pair for transaction signing."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key_bytes, public_key_bytes

    def sign_transaction(self, private_key, transaction):
        """Sign a transaction with the private key."""
        private_key_obj = serialization.load_pem_private_key(private_key, password=None)
        signature = private_key_obj.sign(
            str(transaction).encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, public_key, transaction):
        """Verify the signature of a transaction."""
        public_key_obj = serialization.load_pem_public_key(public_key)
        try:
            public_key_obj.verify(
                transaction['signature'],
                str(transaction).encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False

    @property
    def last_block(self):
        return self.chain[-1]

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['sender'] == address:
                    balance -= transaction['amount']
                if transaction['recipient'] == address:
                    balance += transaction['amount']
        return balance

    def run(self):
        """Start the blockchain and begin processing transactions and blocks."""
        transaction_thread = threading.Thread(target=self.process_transactions)
        transaction_thread.daemon = True  # Allow the thread to exit when the program ends
        transaction_thread.start()

        # Simulate adding a block every 2 minutes
        while True:
            time.sleep(120)  # Wait for 2 minutes
            last_proof = self.last_block['proof']
            proof = self.proof_of_work(last_proof)
            self.new_block(proof)


if __name__ == '__main__':
    blockchain = Blockchain()
    blockchain.run()
