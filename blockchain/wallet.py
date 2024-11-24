import hashlib
from Crypto.PublicKey import RSA

class Wallet:
    def __init__(self, prefix="sasu"):
        while True:
            self.key = RSA.generate(2048)
            self.public_key = self.key.publickey().export_key().decode()
            self.private_key = self.key.export_key().decode()
            # Hash public key to create wallet address
            address_hash = hashlib.sha256(self.public_key.encode()).hexdigest()
            self.address = prefix + address_hash[:36]
            if self.address.startswith(prefix):
                break

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    def get_address(self):
        return self.address
