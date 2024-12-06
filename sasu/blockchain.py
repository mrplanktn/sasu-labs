import hashlib
import json
import time
import os
import threading
import logging
import requests
import validators
from flask import Flask, request, jsonify
from flask_httpauth import HTTPTokenAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from redis import Redis
from dotenv import load_dotenv
from marshmallow import Schema, fields, ValidationError
from cryptography.fernet import Fernet, InvalidToken
from flask_restx import Api
import binascii

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask setup
app = Flask(__name__)

# Flask-RESTx API
api = Api(app, version='1.0', title='Blockchain API',
          description='SASU Blockchain API')

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')

if not SECRET_KEY or not ENCRYPTION_KEY:
    raise Exception('SECRET_KEY and ENCRYPTION_KEY environment variables must be set.')

# Encryption setup
cipher = Fernet(ENCRYPTION_KEY)

# Create Redis connection
def create_redis_connection():
    try:
        client = Redis(
            host='localhost',
            port=6379,
            db=0,
            password=os.getenv('REDIS_PASSWORD'),  # Remove this line if no password is used
            ssl=False  # Set to True if connecting to an SSL-protected Redis
        )
        client.ping()  # Will raise an error if Redis is not reachable
        return client
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise

redis = create_redis_connection()
limiter = Limiter(get_remote_address, app=app, storage_uri="redis://localhost:6379")
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Authentication setup
auth = HTTPTokenAuth(scheme='Bearer')
TOKENS = {
    "valid_token_1": "user1",
    "valid_token_2": "user2"
}

@auth.verify_token
def verify_token(token):
    return TOKENS.get(token)

# Schema for validating transactions
class TransactionSchema(Schema):
    sender = fields.Str(required=True)
    recipient = fields.Str(required=True)
    amount = fields.Float(required=True, validate=lambda x: x > 0)

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.difficulty = 4
        self.nodes = set()
        self.lock = threading.Lock()
        self.load_chain()
        self.miner_wallet_file = "miner_wallet.json"

    def save_chain(self):
        encrypted_chain = cipher.encrypt(json.dumps(self.chain).encode())
        with open('blockchain.json', 'wb') as file:
            file.write(encrypted_chain)

    def load_chain(self):
        if os.path.exists('blockchain.json'):
            with open('blockchain.json', 'rb') as file:
                encrypted_chain = file.read()
            try:
                self.chain = json.loads(cipher.decrypt(encrypted_chain).decode())
            except (InvalidToken, binascii.Error) as e:
                logger.error(f"Decryption failed: {str(e)}")
                self.chain = []  # Reset chain or handle as needed
        else:
            self.chain = []

    def new_transaction(self, sender, recipient, amount):
        # Validasi jumlah harus positif
        if amount <= 0:
            raise ValueError("Amount must be greater than 0")

        # Buat transaksi baru
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount
        }
        self.current_transactions.append(transaction)

        return len(self.chain) + 1

    def new_block(self, proof, previous_hash=None):
        block_reward = 100
        reward_transaction = {
            'sender': None,
            'recipient': self.get_miner_address(),
            'amount': block_reward
        }
        self.current_transactions.append(reward_transaction)

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
        self.broadcast_block(block)
        return block

    def get_miner_address(self):
        if os.path.exists(self.miner_wallet_file):
            with open(self.miner_wallet_file, 'r') as file:
                data = json.load(file)
                return data.get('miner_address', 'default_miner_address')
        return 'default_miner_address'

    def set_miner_address(self, address):
        with open(self.miner_wallet_file, 'w') as file:
            json.dump({'miner_address': address}, file)

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == "0" * self.difficulty

    def hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def broadcast_block(self, block):
        for node in self.nodes:
            if validators.url(node):
                try:
                    response = requests.post(f"{node}/api/blocks/new", json=block)
                    if response.status_code == 201:
                        logger.info(f"Block broadcasted successfully to {node}")
                    else:
                        logger.warning(f"Failed to broadcast block to {node}: {response.text}")
                except Exception as e:
                    logger.error(f"Error broadcasting block to {node}: {str(e)}")

    def is_valid_chain(self, chain):
        for i in range(1, len(chain)):
            previous_block = chain[i - 1]
            current_block = chain[i]
            if current_block['previous_hash'] != self.hash(previous_block):
                logger.error(f"Invalid previous hash at block {i}")
                return False
            if not self.valid_proof(previous_block['proof'], current_block['proof']):
                logger.error(f"Invalid proof of work at block {i}")
                return False
            for transaction in current_block['transactions']:
                if transaction['amount'] <= 0:
                    logger.error(f"Invalid transaction amount at block {i}: {transaction}")
                    return False  # Tambahkan validasi transaksi    
        return True

    def resolve_conflicts(self):
        longest_chain = None
        max_length = len(self.chain)

        for node in self.nodes:
            if validators.url(node):
                try:
                    response = requests.get(f"{node}/api/chain")
                    if response.status_code == 200:
                        length = response.json()['length']
                        chain = response.json()['chain']

                        if length > max_length and self.is_valid_chain(chain):
                            max_length = length
                            longest_chain = chain
                except Exception as e:
                    logger.error(f"Error fetching chain from {node}: {str(e)}")

        if longest_chain:
            self.chain = longest_chain
            self.save_chain()
            return True
        return False    

blockchain = Blockchain()

@app.route('/api/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route('/api/transaction/new', methods=['POST'])
@auth.login_required
@limiter.limit("5 per minute")
def new_transaction():
    values = request.get_json()
    try:
        data = TransactionSchema().load(values)
    except ValidationError as err:
        return jsonify({'message': 'Invalid input', 'errors': err.messages}), 400

    blockchain.current_transactions.append({
        'sender': data['sender'],
        'recipient': data['recipient'],
        'amount': data['amount']
    })

    return jsonify({'message': 'Transaction added successfully'}), 201

@app.route('/api/nodes/register', methods=['POST'])
def register_node():
    values = request.get_json()
    nodes = values.get('nodes')
    if not nodes:
        return jsonify({'message': 'Node addresses are required'}), 400
    
    for node in nodes:
        if not validators.url(node):
            return jsonify({'message': f'Invalid node address: {node}'}), 400
    
    blockchain.nodes.update(nodes)
    return jsonify({'message': 'Nodes added successfully'}), 201

@app.route('/api/mine', methods=['GET'])
@auth.login_required
@limiter.limit("2 per minute")
def mine():
    with blockchain.lock:
        last_block = blockchain.chain[-1] if blockchain.chain else None
        last_proof = last_block['proof'] if last_block else 0
        proof = blockchain.proof_of_work(last_proof)

        # Create a new block
        previous_hash = blockchain.hash(last_block) if last_block else None
        block = blockchain.new_block(proof, previous_hash)

    return jsonify({
        'message': 'New block mined',
        'block': block
    }), 200

@app.route('/api/validate', methods=['GET'])
def validate_chain():
    is_valid = blockchain.is_valid_chain(blockchain.chain)
    return jsonify({'valid': is_valid}), 200

@app.route('/api/consensus', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        message = "The chain was replaced with a longer valid chain."
    else:
        message = "The chain is already the longest valid chain."
    
    return jsonify({'message': message}), 200

@app.route('/')
def home():
    return 'Welcome to the Secure Blockchain API!'

if __name__ == '__main__':
    app.run(debug=True)
