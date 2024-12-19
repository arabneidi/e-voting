from flask import Blueprint, request, jsonify, session, redirect, url_for
from models import User
from utils.auth_utils import send_verification_otp

# Initialize a Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/verify_reset', methods=['POST'])
def verify_reset():
    """
    Route to verify a user's identity for password reset purposes.
    Accepts first name, last name, phone number, country code, and verification type (phone or email).
    """
    try:
        # Collect data from the request
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        phone_number = request.form.get('phone_number', '')
        country_code = request.form.get('country_code', '')
        verification_type = request.form.get('verification_type', '')

        # Concatenate country code and phone number for a full phone number format
        full_phone_number = f"{country_code}{phone_number}"

        # Ensure all required fields are provided
        if not (first_name and last_name and phone_number and verification_type):
            return jsonify(success=False, error="Missing required fields"), 400

        # Locate user in the database
        user = User.query.filter_by(first_name=first_name, last_name=last_name, phone_number=phone_number).first()
        if not user:
            return jsonify(success=False, error="User not found"), 404

        # Verification based on the type (phone or email)
        if verification_type == 'phone' and not user.phone_verified:
            return jsonify(success=False, error="Phone number not verified"), 400
        if verification_type == 'email' and not user.email_verified:
            return jsonify(success=False, error="Email not verified"), 400

        # Send OTP or return security question based on the verification type
        response = send_verification_otp(user, verification_type)
        return jsonify(response)

    except Exception as e:
        # Handle server errors
        return jsonify(success=False, error="Server error occurred"), 500


@auth_bp.route('/logout')
def logout():
    """
    Route to log the user out by clearing the session and redirecting to the login page.
    """
    session.clear()
    return redirect(url_for('login'))
