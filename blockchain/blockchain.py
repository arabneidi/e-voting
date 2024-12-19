from datetime import datetime
from .block import Block

class Blockchain:
    def __init__(self):
        # Initializes the blockchain with a genesis block and an empty list for pending transactions
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []

    # Creates the first block in the blockchain, known as the genesis block
    def create_genesis_block(self):
        # The genesis block has a default reference code, candidate code, and "previous hash" as '0'
        return Block(0, datetime.utcnow().isoformat(), "Genesis", "GEN", "Genesis Block", "0")

    # Returns the latest (most recent) block in the chain
    def get_latest_block(self):
        return self.chain[-1]

    # Adds a new block to the chain
    def add_block(self, block):
        # Appends the block to the end of the chain to maintain the order
        self.chain.append(block)

    # Adds a new transaction to the list of pending transactions
    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    # Mines pending transactions into a new block and appends it to the chain
    def mine_pending_transactions(self):
        # Creates a new block with the first pending transaction
        new_block = Block(
            index=len(self.chain),  # Sets the new block's index to the length of the chain
            timestamp=datetime.utcnow().isoformat(),  # Sets current timestamp
            reference_code=self.pending_transactions[0]['reference_code'],  # Sets reference code from the transaction
            candidate_code=self.pending_transactions[0]['candidate_code'],  # Sets candidate code from the transaction
            encrypted_vote=self.pending_transactions[0]['encrypted_vote'],  # Sets encrypted vote from the transaction
            previous_hash=self.get_latest_block().hash  # Links to the previous block's hash
        )
        # Adds the mined block to the chain and clears pending transactions
        self.add_block(new_block)
        self.pending_transactions = []
