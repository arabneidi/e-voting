from datetime import datetime
from utils.encoding_utils import generate_secure_reference_code
from extensions import voting_blockchain
from utils.encryption_utils import encrypt_vote
from models import Result, Vote

def save_vote_to_db(user, candidate_name, candidate_code):
    """
    Save the user's vote in the database and mark the user as having voted.

    Args:
        user (User): The user who is casting the vote.
        candidate_name (str): Name of the candidate chosen by the user.
        candidate_code (str): Unique code for the selected candidate.

    Returns:
        tuple: A reference code for the vote and the encrypted vote data.
    """
    # Generate a unique reference code for this vote
    reference_code = generate_secure_reference_code()

    # Encrypt the candidate code for secure storage
    encrypted_vote = encrypt_vote(candidate_code)

    # Create a Result record to store the vote details
    result = Result(
        reference_code=reference_code,
        candidate_name=candidate_name,
        candidate_code=candidate_code
    )
    db.session.add(result)

    # Update the user's voting status and log the vote
    user.voted = True
    vote = Vote(voter_id=user.id)
    db.session.add(vote)

    # Commit both the result and vote to the database
    db.session.commit()

    return reference_code, encrypted_vote


def add_vote_to_blockchain(reference_code, candidate_code, encrypted_vote):
    """
    Add the vote as a transaction to the blockchain and mine the new block.

    Args:
        reference_code (str): Unique code associated with the vote.
        candidate_code (str): Unique code of the chosen candidate.
        encrypted_vote (str): Encrypted candidate code.

    """
    # Prepare the transaction data
    new_transaction = {
        'reference_code': reference_code,
        'candidate_code': candidate_code,
        'encrypted_vote': encrypted_vote,
        'timestamp': datetime.utcnow().isoformat()
    }

    # Add the transaction to the blockchain, mine it, and save the new block
    voting_blockchain.add_transaction(new_transaction)
    voting_blockchain.mine_pending_transactions()
    voting_blockchain.save_block_to_db(voting_blockchain.get_latest_block())
