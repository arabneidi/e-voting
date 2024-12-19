import os
import base64
from cryptography.fernet import Fernet

# Load the encryption key from the directory containing app.py
def load_encryption_key():
    # This should point to the directory containing app.py
    key_path = os.path.join(os.path.dirname(__file__), '..', 'secret.key')
    key_path = os.path.abspath(key_path)  # Get absolute path
    with open(key_path, 'rb') as key_file:
        return key_file.read()

# Create the cipher_suite in this module to avoid circular import
cipher_suite = Fernet(load_encryption_key())

def get_cipher_suite():
    """Return the cipher_suite."""
    return cipher_suite

def encrypt_vote(vote):
    """Encrypt the vote and encode it in base64."""
    vote_bytes = str(vote).encode('utf-8')
    encrypted_vote = cipher_suite.encrypt(vote_bytes)
    return base64.b64encode(encrypted_vote).decode('utf-8')

def decrypt_vote(encrypted_vote):
    """Decrypt the base64-encoded encrypted vote."""
    encrypted_vote_bytes = base64.b64decode(encrypted_vote)
    return cipher_suite.decrypt(encrypted_vote_bytes).decode('utf-8')
