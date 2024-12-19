import random
from flask import session
from datetime import datetime, timezone, timedelta
from utils.twilio_utils import send_sms
from utils.email_utils import send_email

def generate_otp():
    """
    Generates a 6-digit OTP.
    """
    return str(random.randint(100000, 999999))


def send_otp_phone(phone_number):
    """
    Sends an OTP via SMS to the specified phone number.

    Args:
        phone_number (str): The user's phone number to send the OTP.

    Returns:
        dict: Contains success status and a message for the frontend.
    """
    try:
        if not phone_number:
            return {'success': False, 'message': 'Phone number is required.'}

        otp_phone = generate_otp()
        send_sms(phone_number, f"Your OTP code is {otp_phone}")

        # Store OTP and generation time in the session for validation
        session['otp_phone'] = otp_phone
        session['otp_generation_time_phone'] = datetime.now(timezone.utc).isoformat()

        return {"success": True, 'message': 'OTP sent successfully to phone.'}
    except Exception as e:
        print(f"Error occurred: {e}")
        return {'success': False, 'message': 'Internal server error.'}


def send_otp_email(email):
    """
    Sends an OTP via email to the specified email address.

    Args:
        email (str): The user's email to send the OTP.

    Returns:
        dict: Contains success status and a message for the frontend.
    """
    try:
        if not email:
            return {'success': False, 'message': 'Email is required.'}

        otp_email = generate_otp()
        send_email(email, "Your OTP Code", f"Your OTP is: {otp_email}")

        # Store OTP and generation time in the session for validation
        session['otp_email'] = otp_email
        session['otp_generation_time_email'] = datetime.now(timezone.utc).isoformat()

        return {"success": True, 'message': 'OTP sent successfully to email.'}
    except Exception as e:
        print(f"Error occurred: {e}")
        return {'success': False, 'message': 'Internal server error.'}


def is_otp_valid(otp_generation_time, expiration_minutes=2):
    """
    Validates if the OTP is within the allowed time frame.

    Args:
        otp_generation_time (datetime or str): OTP generation timestamp.
        expiration_minutes (int): Minutes for OTP validity.

    Returns:
        bool: True if OTP is still valid, False otherwise.
    """
    # Convert to datetime if given as a string
    if isinstance(otp_generation_time, str):
        otp_generation_time = datetime.strptime(otp_generation_time, '%Y-%m-%d %H:%M:%S%z')

    # Checks if the OTP is still within the expiration time window
    return datetime.now(timezone.utc) - otp_generation_time <= timedelta(minutes=expiration_minutes)


def send_otp(destination, otp, method='phone'):
    """
    Sends OTP to the user's phone or email.

    Args:
        destination (str): Phone number or email address for OTP.
        otp (str): The OTP code to send.
        method (str): Method for sending ('phone' or 'email').

    Raises:
        ValueError: If method is neither 'phone' nor 'email'.
    """
    session['otp'] = otp
    session['otp_generation_time'] = datetime.now(timezone.utc).isoformat()

    message = f"Your OTP code is {otp}"
    if method == 'phone':
        send_sms(destination, message)
    elif method == 'email':
        send_email(destination, "Your OTP Code", message)
    else:
        raise ValueError("Invalid method for OTP delivery")
