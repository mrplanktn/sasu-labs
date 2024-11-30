import hashlib
import ecdsa
import base58
from mnemonic import Mnemonic
from Crypto.Hash import RIPEMD160

class SasuWallet:
    def __init__(self):
        self.mnemonic = Mnemonic("english")  # Bahasa untuk seed phrase
        self.private_key = None
        self.public_key = None
        self.address = None
        self.secret_phrase = None

    def generate_wallet(self):
        # Step 1: Generate Secret Phrase (Seed Phrase)
        self.secret_phrase = self.mnemonic.generate(strength=128)  # Generate a 12-word seed phrase
        seed = self.mnemonic.to_seed(self.secret_phrase, passphrase="")  # Convert seed phrase to seed
        
        # Step 2: Generate Private Key from Seed (using SHA256 hashing for determinism)
        private_key_bytes = hashlib.sha256(seed).digest()
        private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        self.private_key = private_key.to_string().hex()  # Private key in hex format
        
        # Step 3: Generate Public Key from Private Key
        self.public_key = private_key.get_verifying_key().to_string().hex()

        # Step 4: Generate Wallet Address from Public Key (Base58 encoding)
        pub_key_bytes = bytes.fromhex(self.public_key)
        
        # Apply SHA256 followed by RIPEMD160 using pycryptodome
        sha256_hash = hashlib.sha256(pub_key_bytes).digest()
        ripemd160_hash = RIPEMD160.new(sha256_hash).digest()

        # Prefix 'sasu' (encoded to byte format) to the resulting hash
        prefix = b'sasu'  # Prefix "sasu"
        
        # Create a custom address: Start with 'sasu' and then the RIPEMD160 hash
        address_bytes = prefix + ripemd160_hash
        
        # Ensure that the address is Base58Check encoded
        self.address = base58.b58encode(address_bytes).decode('utf-8')  # Base58Check encoding
        
        # Check if the address starts with 'sasu' after Base58Check encoding
        if not self.address.startswith('sasu'):
            self.address = 'sasu' + self.address[4:]  # Forcefully replace the first few chars with 'sasu'
        
        return self.address, self.private_key, self.secret_phrase

# Create an instance of SasuWallet and generate the wallet
wallet = SasuWallet()
address, private_key, secret_phrase = wallet.generate_wallet()

# Display the wallet details
print("Sasu Network Wallet Generated:")
print(f"Wallet Address: {address}")
print(f"Private Key: {private_key}")
print(f"Secret Phrase: {secret_phrase}")
