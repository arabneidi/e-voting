from extensions import db
from datetime import date, datetime

# Represents a blockchain block with necessary details for blockchain integrity
class BlockchainModel(db.Model):
    __tablename__ = 'blockchain'

    id = db.Column(db.Integer, primary_key=True)
    block_index = db.Column(db.Integer, nullable=False)  # Position of the block in the chain
    timestamp = db.Column(db.DateTime, nullable=False)  # When the block was created
    reference_code = db.Column(db.String(24), nullable=False)  # Unique reference code for the vote
    candidate_code = db.Column(db.String(10), nullable=False)  # Code of the candidate being voted for
    encrypted_vote = db.Column(db.String(500), nullable=False)  # Encrypted vote details for privacy
    previous_hash = db.Column(db.String(64), nullable=False)  # Hash of the previous block
    block_hash = db.Column(db.String(64), nullable=False)  # Current block's hash for integrity check

    def __init__(self, block_index, timestamp, reference_code, candidate_code, encrypted_vote, previous_hash, block_hash):
        self.block_index = block_index
        self.timestamp = timestamp
        self.reference_code = reference_code
        self.candidate_code = candidate_code
        self.encrypted_vote = encrypted_vote
        self.previous_hash = previous_hash
        self.block_hash = block_hash


# Admin model to store admin user information
class Admin(db.Model):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)  # Unique username for login
    password = db.Column(db.String(128), nullable=False)  # Hashed password
    totp_secret = db.Column(db.String(32), nullable=True)  # Google Authenticator TOTP secret

    def __repr__(self):
        return f'<Admin {self.username}>'


# User model representing each registered voter
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    country_code = db.Column(db.String(10), nullable=False)  # Country code for phone numbers
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    phone_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    question = db.Column(db.String(50), nullable=False)  # Security question for account recovery
    answer = db.Column(db.String(100), nullable=False)  # Answer to the security question
    image = db.Column(db.LargeBinary)  # ID card image for verification
    voted = db.Column(db.Boolean, default=False)  # Voting status
    bank_id = db.Column(db.Integer, db.ForeignKey('bank.id'), nullable=True)  # Foreign key to Bank table

    # Relationship with the Bank model
    bank = db.relationship("Bank", back_populates="user", lazy=True)


# Bank model containing personal and contact details
class Bank(db.Model):
    __tablename__ = 'bank'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    identification_number = db.Column(db.String(50), unique=True, nullable=False)  # Unique ID for verification
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    country_code = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    birthdate = db.Column(db.Date, nullable=False)  # Date of birth
    postal_code = db.Column(db.String(10), nullable=True)  # Postal code for address verification
    death_date = db.Column(db.Date, nullable=True)  # Null means the person is alive

    # Relationship with the User model
    user = db.relationship("User", back_populates="bank", uselist=False, lazy=True)

    # Calculate the age based on birthdate
    @property
    def age(self):
        if self.birthdate:
            today = date.today()
            return today.year - self.birthdate.year - ((today.month, today.day) < (self.birthdate.month, self.birthdate.day))
        return None


# Model for each vote cast by a user
class Vote(db.Model):
    __tablename__ = 'vote'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Reference to the user who voted
    cast_time = db.Column(db.DateTime, default=datetime.utcnow)  # Time the vote was cast

    # Relationship to the User model for easy reference
    voter = db.relationship('User', backref=db.backref('votes', lazy=True))

    def __repr__(self):
        return f'<Vote id={self.id}, voter_id={self.voter_id}, cast_time={self.cast_time}>'


# Model for storing election results
class Result(db.Model):
    __tablename__ = 'result'

    id = db.Column(db.Integer, primary_key=True)
    reference_code = db.Column(db.String(24), unique=True, nullable=False)  # Reference code for the vote
    candidate_name = db.Column(db.String(100), nullable=False)  # Candidate's name
    candidate_code = db.Column(db.String(10), nullable=False)  # Candidate's unique code
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Time the result was stored

    def __init__(self, reference_code, candidate_name, candidate_code):
        self.reference_code = reference_code
        self.candidate_name = candidate_name
        self.candidate_code = candidate_code


# Model for election settings
class Settings(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    election_type = db.Column(db.Integer, nullable=False)  # 1 for federal, 2 for provincial, 3 for territorial
    election_name = db.Column(db.String(255), nullable=True)  # Name of the election
    start_time = db.Column(db.DateTime, nullable=False)  # Start time of the election
    end_time = db.Column(db.DateTime, nullable=False)  # End time of the election
    extend_time = db.Column(db.Integer, default=0)  # Additional time in minutes for the election


# Model for federal ridings
class FederalRiding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    riding_code = db.Column(db.String(10), unique=True, nullable=False)  # Code for the riding
    riding_name = db.Column(db.String(255), nullable=False)  # Riding's name
    candidate_code = db.Column(db.String(10), nullable=False)  # Code for the candidate
    candidate_name = db.Column(db.String(255), nullable=False)  # Candidate's name
    candidate_party = db.Column(db.String(255), nullable=False)  # Party of the candidate


# Model for provincial ridings
class ProvincialRiding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    province = db.Column(db.String(255), nullable=False)  # Province name
    riding_code = db.Column(db.String(10), unique=True, nullable=False)  # Riding's code
    riding_name = db.Column(db.String(255), nullable=False)  # Riding's name
    candidate_code = db.Column(db.String(10), nullable=False)  # Code for the candidate
    candidate_name = db.Column(db.String(255), nullable=False)  # Candidate's name
    candidate_party = db.Column(db.String(255), nullable=False)  # Party of the candidate


# Model for territorial ridings
class TerritorialRiding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    territory = db.Column(db.String(255), nullable=False)  # Territory name
    riding_code = db.Column(db.String(10), unique=True, nullable=False)  # Riding's code
    riding_name = db.Column(db.String(255), nullable=False)  # Riding's name
    candidate_code = db.Column(db.String(10), nullable=False)  # Code for the candidate
    candidate_name = db.Column(db.String(255), nullable=False)  # Candidate's name
    candidate_party = db.Column(db.String(255), nullable=False)  # Party of the candidate
