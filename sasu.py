import hashlib
import json
import time
import random
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from concurrent.futures import ThreadPoolExecutor

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.difficulty = 4  # Proof-of-work difficulty
        self.validators = {}  # Staking pool for PoS
        self.transaction_pool = []  # Pool of unconfirmed transactions
        self.validator_lock = threading.Lock()  # Lock for validator updates
        self.transaction_lock = threading.Lock()  # Lock for transaction handling
        self.executor = ThreadPoolExecutor(max_workers=10)  # Parallel transaction processing
        self.new_block(previous_hash='1', proof=100)  # Genesis block

    def new_block(self, proof, previous_hash=None):
        """Generate a new block and add it to the chain."""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': self.generate_proof_of_history(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]) if self.chain else None,
        }
        self.current_transactions = []  # Reset the current transactions list
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """Create a new transaction and add it to the transaction pool."""
        if self.get_balance(sender) < amount:
            raise Exception("Insufficient funds for transaction.")
        
        transaction = {'sender': sender, 'recipient': recipient, 'amount': amount}
        
        # Ensure thread safety when adding to the transaction pool
        with self.transaction_lock:
            self.transaction_pool.append(transaction)
        
        return self.last_block['index'] + 1

    def process_transactions(self):
        """Process transactions in batches."""
        while True:
            if len(self.transaction_pool) >= 10:
                # Get the first 10 transactions for processing
                transaction_batch = self.transaction_pool[:10]
                # Remove processed transactions from the pool
                with self.transaction_lock:
                    self.transaction_pool = self.transaction_pool[10:]

                # Process batch in parallel
                self.executor.submit(self.add_transactions_to_block, transaction_batch)

    def add_transactions_to_block(self, transaction_batch):
        """Add validated transactions to the current block."""
        for transaction in transaction_batch:
            if not self.verify_signature(transaction['sender'], transaction):
                print(f"Invalid signature for transaction: {transaction}")
                continue  # Skip invalid transactions

            if self.get_balance(transaction['sender']) < transaction['amount']:
                print(f"Insufficient balance for transaction: {transaction}")
                continue  # Skip transactions with insufficient balance

            # Add valid transaction to current block
            self.current_transactions.append(transaction)

    def hash(self, block):
        """Create SHA-256 hash for a block."""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def generate_proof_of_history(self):
        """Generate a unique proof of history."""
        return hashlib.sha256(f"{time.time()}".encode()).hexdigest()

    def proof_of_work(self, last_proof):
        """Proof-of-work algorithm to find the next proof."""
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        """Validate the proof of work."""
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == "0" * self.difficulty

    def stake(self, validator_address, amount):
        """Add a stake to the validator."""
        with self.validator_lock:
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
        """Generate a private-public key pair."""
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
        transaction['signature'] = signature
        return transaction

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
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")
            return False

    @property
    def last_block(self):
        return self.chain[-1]

    def get_balance(self, address):
        """Get the balance of an address."""
        balance = 0
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['sender'] == address:
                    balance -= transaction['amount']
                if transaction['recipient'] == address:
                    balance += transaction['amount']
        return balance

    def get_chain(self):
        """Return the entire blockchain as a JSON string."""
        return json.dumps(self.chain, indent=4)

    def run(self):
        """Start the blockchain and begin processing transactions and blocks."""
        print("Blockchain started")  # Debugging output
        transaction_thread = threading.Thread(target=self.process_transactions)
        transaction_thread.daemon = True  # Allow the thread to exit when the program ends
        transaction_thread.start()

        # Simulate adding a block every 2 minutes
        while True:
            print("Waiting to add a new block...")  # Debugging output
            time.sleep(120)  # Wait time for adding blocks
            last_proof = self.last_block['proof']
            proof = self.proof_of_work(last_proof)
            self.new_block(proof)
            print("New block added")  # Debugging output

# Menjalankan blockchain
if __name__ == '__main__':
    blockchain = Blockchain()
    blockchain.run()
