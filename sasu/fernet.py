from cryptography.fernet import Fernet

# Generate a new Fernet key
key = Fernet.generate_key()
print(key.decode())  # Print the key to set as the ENCRYPTION_KEY in your .env