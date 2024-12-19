import hashlib
import json

class Block:
    # Initializes a Block with necessary vote information and calculates its hash
    def __init__(self, index, timestamp, reference_code, candidate_code, encrypted_vote, previous_hash=''):
        self.index = index  # Unique position of the block in the chain
        self.timestamp = timestamp  # The exact time the vote was cast
        self.reference_code = reference_code  # Unique code referencing the specific vote
        self.candidate_code = candidate_code  # Code identifying the chosen candidate
        self.encrypted_vote = encrypted_vote  # The encrypted vote data for added security
        self.previous_hash = previous_hash  # The hash of the preceding block, linking the chain
        self.hash = self.calculate_hash()  # Calculates and assigns the block's unique hash

    # Calculates the hash for the block based on its contents
    def calculate_hash(self):
        # Converts the block's content to JSON, sorts keys to ensure consistency, and encodes to bytes
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'reference_code': self.reference_code,
            'candidate_code': self.candidate_code,
            'encrypted_vote': self.encrypted_vote,
            'previous_hash': self.previous_hash
        }, sort_keys=True).encode()

        # Returns the SHA-256 hash of the block's contents
        return hashlib.sha256(block_string).hexdigest()

    # Converts the block's data to a dictionary for easy export or inspection
    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'reference_code': self.reference_code,
            'candidate_code': self.candidate_code,
            'encrypted_vote': self.encrypted_vote,
            'previous_hash': self.previous_hash,
            'hash': self.hash  # The calculated hash of this block
        }
