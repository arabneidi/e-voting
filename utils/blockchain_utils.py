import json
from extensions import db

def save_blockchain_to_db(voting_blockchain):
    """Serialize the blockchain and save it to the database."""
    blockchain_state = json.dumps([block.__dict__ for block in voting_blockchain.chain])
    query = "INSERT INTO blockchain (chain) VALUES (%s)"
    db.session.execute(query, (blockchain_state,))
    db.session.commit()
