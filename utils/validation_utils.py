from flask import session
import re

def validate_password_strength(password, confirm_password):
    if password != confirm_password:
        return False, "Passwords do not match."
    if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
        return False, "Password must be at least 8 characters long, contain an uppercase letter, and a number."
    return True, ""

def verify_otp(phone_number=None, email=None, entered_otp_phone=None, entered_otp_email=None):
    if phone_number and ('otp_phone' not in session or entered_otp_phone != session.get('otp_phone')):
        return False, "Phone OTP is incorrect or expired."
    if email and ('otp_email' not in session or entered_otp_email != session.get('otp_email')):
        return False, "Email OTP is incorrect or expired."
    return True, ""


def validate_email_format(email):
    """Validate email format using regex."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

