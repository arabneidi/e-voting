from flask import Blueprint, jsonify, request  # Import Flask modules for blueprint and JSON responses
from utils.blockchain_utils import save_blockchain_to_db  # Import blockchain instance and saving function
from extensions import voting_blockchain

# Create a new Blueprint instance for blockchain-related routes
blockchain_bp = Blueprint('blockchain', __name__)

# Route to verify the blockchain's integrity
@blockchain_bp.route('/verify_blockchain', methods=['GET'])
def verify_blockchain():
    """
    Verifies the integrity of the blockchain.
    Returns a message indicating whether the blockchain is valid or compromised.
    """
    # Check if the blockchain is valid by calling `is_chain_valid`
    if voting_blockchain.is_chain_valid():
        return jsonify({"message": "Blockchain is valid."})  # Return success message if valid
    else:
        return jsonify({"message": "Blockchain integrity compromised."}), 400  # Return error if compromised

# Route to save the blockchain to the database
@blockchain_bp.route('/save_blockchain', methods=['POST'])
def save_blockchain():
    """
    Saves the current blockchain state to the database.
    Returns a success message if saved successfully, otherwise an error message.
    """
    try:
        save_blockchain_to_db(voting_blockchain)  # Attempt to save blockchain data to the database
        return jsonify({"message": "Blockchain saved successfully!"})  # Return success message
    except Exception as e:
        print(f"Error saving blockchain: {e}")  # Log error for debugging
        return jsonify({"message": "Failed to save blockchain."}), 500  # Return error message on failure
