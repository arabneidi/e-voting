from backend.models import BlockchainModel  # Import the BlockchainModel class for database operations
from backend import db  # Import the database instance for session management


def save_block_to_db(new_block):
    """
    Saves a new blockchain block to the database.
    """
    # Prepare the data for the new block to match the database schema
    block_data = {
        'block_index': new_block.index,  # Block's index in the chain
        'timestamp': new_block.timestamp,  # Timestamp of the block creation
        'reference_code': new_block.reference_code,  # Reference code associated with the block
        'candidate_code': new_block.candidate_code,  # Candidate code for the vote
        'encrypted_vote': new_block.encrypted_vote,  # Encrypted vote data
        'previous_hash': new_block.previous_hash,  # Hash of the previous block to ensure chain integrity
        'block_hash': new_block.hash  # Hash of the current block for integrity verification
    }

    # Create a new BlockchainModel instance with the block data
    blockchain_entry = BlockchainModel(**block_data)

    # Add the block entry to the session and commit it to the database
    db.session.add(blockchain_entry)
    db.session.commit()  # Commit to save the new block in the database
