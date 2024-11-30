import hashlib
import json
import time
import os
import threading
import logging
import jwt as pyjwt
from flask import Flask, request, jsonify 
from functools import wraps, lru_cache
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from redis import Redis

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Flask setup
app = Flask(__name__)

# Redis dan Flask-Limiter konfigurasi
redis = Redis(host='localhost', port=6379, db=0)
limiter = Limiter(get_remote_address, app=app, storage_uri="redis://localhost:6379")
CORS(app, resources={r"/api/*": {"origins": ["https://yourdomain.com"]}})  # adjust this for testing or local use

# Load environment variables
SECRET_KEY = os.getenv('SECRET_KEY', 'default_unsafe_secret')

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.difficulty = 4
        self.nodes = set()
        self.completed_transactions = set()
        self.lock = threading.Lock()
        self.load_chain()

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]) if self.chain else None,
        }
        self.current_transactions = []
        self.chain.append(block)
        self.save_chain()
        self.adjust_difficulty()
        return block

    def new_transaction(self, sender, recipient, amount, public_key, signature):
        transaction = {'sender': sender, 'recipient': recipient, 'amount': amount}

        if not self.verify_transaction(public_key, transaction, signature):
            raise Exception("Invalid transaction signature.")

        if self.get_balance(sender) < amount:
            raise Exception("Insufficient funds for transaction.")

        transaction_hash = hashlib.sha256(json.dumps(transaction).encode()).hexdigest()

        with self.lock:
            if transaction_hash in self.completed_transactions:
                raise Exception("Duplicate transaction detected!")
            self.completed_transactions.add(transaction_hash)
            self.current_transactions.append(transaction)

        return self.last_block['index'] + 1

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @lru_cache(maxsize=128)
    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == "0" * self.difficulty

    @lru_cache(maxsize=128)
    def hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block.get('transactions', []):
                if transaction['sender'] == address:
                    balance -= transaction['amount']
                if transaction['recipient'] == address:
                    balance += transaction['amount']
        return balance

    def save_chain(self):
        with open('blockchain.json', 'w') as file:
            json.dump(self.chain, file, indent=4)

    def load_chain(self):
        if os.path.exists('blockchain.json'):
            with open('blockchain.json', 'r') as file:
                self.chain = json.load(file)
        else:
            self.chain = []

    def adjust_difficulty(self):
        if len(self.chain) < 2:
            return
        last_block = self.chain[-1]
        second_last_block = self.chain[-2]
        time_taken = last_block['timestamp'] - second_last_block['timestamp']
        if time_taken < 5 * 60:
            self.difficulty += 1
        elif time_taken > 15 * 60:
            self.difficulty = max(1, self.difficulty - 1)

    def verify_transaction(self, public_key, transaction, signature):
        public_key_obj = serialization.load_pem_public_key(public_key)
        try:
            public_key_obj.verify(
                bytes.fromhex(signature),
                json.dumps(transaction, sort_keys=True).encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None


blockchain = Blockchain()

@app.route('/api/auth', methods=['POST'])
def auth():
    try:
        values = request.get_json()
        app.logger.debug(f"Request JSON: {values}")  # Tambahkan log ini
        if not values:
            return jsonify({'message': 'Missing or invalid JSON'}), 400
        if values.get('username') == 'admin' and values.get('password') == 'password':
            token = pyjwt.encode({'user': 'admin', 'exp': time.time() + 600}, SECRET_KEY, algorithm='HS256')
            return jsonify({'token': token})
        return jsonify({'message': 'Invalid credentials'}), 403
    except Exception as e:
        app.logger.error(f"Error in /api/auth: {e}")  # Log error
        return jsonify({'message': 'Internal Server Error'}), 500


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Unauthorized'}), 403
        token = token.split(" ")[1] if len(token.split()) > 1 else ''
        try:
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except Exception:
            return jsonify({'message': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/transactions/new', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'public_key', 'signature']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400
    try:
        index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], values['public_key'], values['signature'])
    except Exception as e:
        return jsonify({'message': str(e)}), 400
    return jsonify({'message': f'Transaction will be added to Block {index}'}), 201

@app.route('/api/mine', methods=['POST'])
@require_auth
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof'] if last_block else 0
    proof = blockchain.proof_of_work(last_proof)
    blockchain.new_block(proof, previous_hash=blockchain.hash(last_block) if last_block else None)
    return jsonify({'message': 'New block mined', 'block': blockchain.last_block}), 201

@app.route('/api/chain', methods=['GET'])
def full_chain():
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200

@app.route('/')
def fuck_error():
    app.logger.debug('This is a debug log.')
    return 'FUCK'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
