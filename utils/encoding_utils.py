import os
import hashlib
import string


def base62_encode(byte_string):
    """Encode a byte string in base62 (letters and digits)."""
    characters = string.ascii_letters + string.digits
    base = len(characters)
    num = int.from_bytes(byte_string, 'big')
    encoded = []

    while num > 0:
        num, rem = divmod(num, base)
        encoded.append(characters[rem])

    return ''.join(reversed(encoded))


def generate_secure_reference_code(election_id="ELEC2024", length=24):
    """Generate a secure reference code for an election."""
    # Generate a secure random 32-byte string for high entropy
    random_bytes = os.urandom(32)  # 256 bits of entropy

    # Hash it using SHA-256 for additional randomness
    hash_value = hashlib.sha256(random_bytes).digest()

    # Encode the hash using Base62 and truncate
    reference_code = base62_encode(hash_value)[:16]

    # Combine with the election ID
    secure_reference_code = f"{election_id[:8]}-{reference_code}"

    return secure_reference_code[:length]  # Ensure the code length
