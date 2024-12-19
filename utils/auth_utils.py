import pyotp
from flask import session
from models import User
from datetime import datetime, timezone
from utils.otp_utils import send_otp_phone, send_otp_email
from utils.twilio_utils import send_sms
from utils.email_utils import send_email
import random

def validate_password_strength(password):
    """
    Checks if a password meets specified strength criteria.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    return True, ""

def validate_google_authenticator(secret, code):
    """
    Verifies a Google Authenticator TOTP code against a stored secret.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def find_user(first_name, last_name, phone_number):
    """
    Retrieves a user based on first name, last name, and phone number.
    """
    return User.query.filter_by(first_name=first_name, last_name=last_name, phone_number=phone_number).first()

def send_verification(verification_type, user):
    """
    Sends OTP or security question based on the specified verification type.
    """
    if verification_type == 'security_question':
        return {"success": True, "security_question": user.question}
    elif verification_type == 'phone':
        send_otp_phone(user.phone_number)
        return {"success": True, "otp_sent": True}
    elif verification_type == 'email':
        send_otp_email(user.email)
        return {"success": True, "otp_sent": True}
    return {"success": False, "error": "Invalid verification type."}

def verify_otp(entered_otp, otp_type):
    """
    Verifies OTP from session for a specified type ('phone' or 'email').
    """
    otp_in_session = session.get(f'otp_{otp_type}')

    if not otp_in_session:
        return False

    if entered_otp == otp_in_session:
        return True
    else:
        return False

def verify_otp_phone(entered_otp):
    """
    Wrapper to verify OTP for phone.
    """
    return verify_otp(entered_otp, 'phone')

def verify_otp_email(entered_otp):
    """
    Wrapper to verify OTP for email.
    """
    return verify_otp(entered_otp, 'email')

def send_verification_otp(user, verification_type):
    """
    Sends OTP for phone or email, or returns the security question.
    """
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp
    session['otp_generation_time'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S%z')

    if verification_type == 'phone':
        send_sms(user.phone_number, f"Your OTP code is {otp}")
        return {"success": True, "message": "OTP sent to phone"}
    elif verification_type == 'email':
        send_email(user.email, "Your OTP Code", f"Your OTP code is {otp}")
        return {"success": True, "message": "OTP sent to email"}
    elif verification_type == 'security_question':
        return {"success": True, "security_question": user.question}

    return {"success": False, "error": "Invalid verification type"}
