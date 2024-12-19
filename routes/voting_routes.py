# Importing necessary libraries and modules from Flask, utility functions, and models
from flask import Blueprint, request, jsonify, render_template, session, redirect, flash, url_for
from models import User, Bank, Settings
from datetime import datetime, timezone
from utils.ocr_utils import extract_id_card_number
from utils.validation_utils import validate_password_strength, validate_email_format, verify_otp
from utils.recaptcha_utils import verify_recaptcha_v3
from utils.otp_utils import is_otp_valid, generate_otp, send_otp
from utils.election_utils import get_riding_by_postal_code, get_candidates_by_riding
import bcrypt
from extensions import db
import pytz
import requests
from utils.vote_utils import save_vote_to_db, add_vote_to_blockchain
from utils.notification_utils import send_vote_confirmation
from utils.auth_utils import find_user, send_verification

# Define a blueprint for voter-related routes to organize routes under 'voter' namespace
voter_bp = Blueprint('voter', __name__)

@voter_bp.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            # Collect form data
            data = request.form
            first_name, last_name = data['first_name'], data['last_name']
            username, country_code = data['username'], data['country_code']
            phone_number, email = data['phone_number'], data['email']
            password, confirm_password = data['password'], data['confirm_password']
            security_question, security_answer = data['security_question'], data['security_answer']
            entered_otp_phone, entered_otp_email = data['otp_phone'], data['otp_email']
            recaptcha_token = data.get('recaptchaToken')

            # Validate required fields and reCAPTCHA token
            if not (first_name and last_name and username and country_code and (phone_number or email) and password and confirm_password):
                return jsonify(success=False, message="All fields are required.")
            if not verify_recaptcha_v3(recaptcha_token):
                return jsonify(success=False, message="reCAPTCHA verification failed.")
            if email and not validate_email_format(email):
                return jsonify(success=False, message="Invalid email format.")

            # Validate password strength
            is_valid, msg = validate_password_strength(password, confirm_password)
            if not is_valid:
                return jsonify(success=False, message=msg)

            # Check if email, phone, or username already exists in the database
            if email and User.query.filter_by(email=email).first():
                return jsonify(success=False, message="Email is already registered.")
            if phone_number and User.query.filter_by(phone_number=phone_number).first():
                return jsonify(success=False, message="Phone number is already registered.")
            if User.query.filter_by(username=username).first():
                return jsonify(success=False, message="Username is already taken.")

            # Validate against bank records using ID card details
            id_card_number = extract_id_card_number(request.files['id_card'])
            bank_record = Bank.query.filter_by(identification_number=id_card_number).first()
            if not bank_record:
                return jsonify(success=False, message="Your information is not correct.")
            if phone_number and bank_record.phone_number != phone_number:
                return jsonify(success=False, message="Phone number does not match our records.")
            if email and bank_record.email != email:
                return jsonify(success=False, message="Email does not match our records.")
            if bank_record.death_date:
                return jsonify(success=False, message="You are not allowed to vote.")

            # Verify age requirement for voting eligibility
            today = datetime.today()
            age = today.year - bank_record.birthdate.year - ((today.month, today.day) < (bank_record.birthdate.month, bank_record.birthdate.day))
            if age < 18:
                return jsonify(success=False, message="You must be at least 18 years old to register and vote.")

            # OTP validation for phone and email
            otp_valid, otp_msg = verify_otp(phone_number, email, entered_otp_phone, entered_otp_email)
            if not otp_valid:
                return jsonify(success=False, message=otp_msg)

            # Hash the password and save the new user to the database
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(
                first_name=first_name,
                last_name=last_name,
                username=username,
                country_code=country_code,
                phone_number=phone_number,
                email=email,
                question=security_question,
                answer=security_answer,
                password=hashed_pw,
                image=request.files['id_card'].read(),
                phone_verified=(entered_otp_phone == session.get('otp_phone')),
                email_verified=(entered_otp_email == session.get('otp_email'))
            )
            db.session.add(new_user)
            db.session.commit()

            # Clear OTPs after successful registration
            session.pop('otp_phone', None)
            session.pop('otp_email', None)

            return jsonify(success=True, message="Registration successful. Redirecting to login page...")

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify(success=False, message="An error occurred. Please try again.")

    return render_template('register.html')

# Route to verify OTP
@voter_bp.route('/verify_otp', methods=['POST'])
def verify_otp():
    entered_otp = request.json.get('otp')

    # Check if OTP exists, matches the entered one, and is within the validity period
    if 'otp' in session and session['otp'] == entered_otp:
        if is_otp_valid(session.get('otp_generation_time')):
            return jsonify({'success': True, 'message': 'OTP verified.'})

    return jsonify({'success': False, 'message': 'Invalid or expired OTP.'})

# Route to verify the phone number by checking OTP sent to the user
@voter_bp.route('/verify_phone_number/<int:user_id>', methods=['GET', 'POST'])
def verify_phone_number(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found."

    if request.method == 'POST':
        otp = request.form['otp']
        if user.otp == otp and is_otp_valid(user.otp_generation_time):
            user.phone_verified = True
            db.session.commit()
            return redirect(url_for('voter.login'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return render_template('verify_phone.html', user_id=user_id)

    return render_template('verify_phone.html', user_id=user_id)

# Route to display voting options based on user's riding and election type
@voter_bp.route('/voting')
def voting():
    settings = Settings.query.first()
    if not settings:
        flash('No election defined. Please contact support.', 'danger')
        return redirect(url_for('home'))

    voter_id = session.get('voter_id')
    if not voter_id:
        return redirect(url_for('voter.login'))

    user = User.query.get(voter_id)
    if not user:
        flash('Voter not found in the user records. Please contact support.', 'danger')
        return redirect(url_for('home'))

    # Fetch voter details from the bank records to retrieve their riding
    voter = Bank.query.filter_by(email=user.email, phone_number=user.phone_number).first()
    if not voter:
        flash('Voter not found in the bank records. Please contact support.', 'danger')
        return redirect(url_for('home'))

    # Determine riding and fetch candidates based on election type
    riding_code = get_riding_by_postal_code(voter.postal_code)
    if not riding_code:
        flash('Unable to find riding for your postal code. Please contact support.', 'danger')
        return redirect(url_for('home'))

    candidates = get_candidates_by_riding(settings.election_type, riding_code)
    if not candidates:
        flash('No candidates found for your riding. Please contact support.', 'danger')
        return redirect(url_for('home'))

    return render_template('voting.html', candidates=candidates)

# Route for user login
@voter_bp.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user_ip = data.get('user_ip')
        security_answer = data.get('security_answer', '')
        recaptcha_token = data.get('recaptcha_token')

        try:
            # Verify reCAPTCHA token
            if not verify_recaptcha_v3(recaptcha_token):
                return jsonify(success=False, message="reCAPTCHA verification failed. Please try again.")

            # Check if user exists by username
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify(success=False, message="User not found. Please check your username.")

            # Check password validity
            if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                return jsonify(success=False, message="Incorrect password. Please try again.")

            # Fetch current user's country based on IP address
            current_country_data = requests.get(f'https://ipapi.co/{user_ip}/json/').json()
            current_country_code = current_country_data.get('country_calling_code', '')
            if current_country_code != user.country_code:
                # Verify security question if IP-based country code does not match
                if not security_answer:
                    return jsonify(success=False, show_security_question=True, security_question=user.question)
                elif security_answer.lower() != user.answer.lower():
                    return jsonify(success=False, message="Incorrect answer to security question.")
                else:
                    session['logged_in'] = True
                    session['voter_id'] = user.id
                    return jsonify(success=True, redirect_url=url_for('voter.home'))

            # Successful login
            session['logged_in'] = True
            session['voter_id'] = user.id
            return jsonify(success=True, message="Login successful. Redirecting to /home...")

        except Exception as e:
            print(f"An error occurred during login: {e}")
            return jsonify(success=False, message="An error occurred. Please try again.")

    return render_template('login.html')

# Route to render home page with election status
@voter_bp.route('/home')
def home():
    settings = Settings.query.first()

    if not settings:
        return render_template('home.html', election_defined=False)

    # Calculate election status and countdown
    now = datetime.now(pytz.UTC)
    start_time = settings.start_time.astimezone(pytz.UTC)
    end_time = settings.end_time.astimezone(pytz.UTC)

    if now > end_time:
        return render_template('home.html', election_defined=True, election_finished=True)

    if now < start_time:
        countdown_time = (start_time - now).total_seconds()
        return render_template('home.html', election_defined=True, election_started=False, countdown_time=countdown_time)

    remaining_time = (end_time - now).total_seconds()
    voter_id = session.get('voter_id')
    user = User.query.get(voter_id)
    has_voted = user.voted if user else False

    return render_template('home.html', election_defined=True, election_started=True, remaining_time=remaining_time, has_voted=has_voted)

# Route to cast a vote and log it in the blockchain
@voter_bp.route('/cast_vote', methods=['POST'])
def cast_vote():
    if 'logged_in' not in session:
        return jsonify({"message": "User not logged in"}), 401

    voter_id = session.get('voter_id')
    user = User.query.get(voter_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    if user.voted:
        return jsonify({"message": "You have already voted!"}), 400

    data = request.get_json()
    candidate_name = data.get('candidate_name')
    candidate_code = data.get('candidate_code')
    if not candidate_name or not candidate_code:
        return jsonify({"message": "No candidate selected"}), 400

    try:
        # Save the vote to the database and blockchain
        reference_code, encrypted_vote = save_vote_to_db(user, candidate_name, candidate_code)
        add_vote_to_blockchain(reference_code, candidate_code, encrypted_vote)
        send_vote_confirmation(user, reference_code)

    except Exception as e:
        print(f"Error while saving vote: {e}")
        return jsonify({"message": "Failed to record vote. Please try again."}), 500

    return jsonify({"message": "Vote cast successfully!", "reference_code": reference_code})

# Route to check the user's voting status
@voter_bp.route('/audit')
def audit_page():
    if 'logged_in' not in session:
        return redirect(url_for('voter.login'))

    voter_id = session.get('voter_id')
    user = User.query.get(voter_id)

    if not user:
        return render_template('audit.html', message="User not found.")

    if not user.voted:
        return render_template('audit.html', message="You have not voted yet.")

    return render_template('audit.html', message="You have voted successfully.")

# Route to reset password through OTP or security question
@voter_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        action_type = request.form.get('action_type', '')

        # Verify user and send OTP or security question based on user selection
        if action_type == 'verify_method':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            phone_number = request.form['phone_number']
            verification_type = request.form['verification_type']

            user = find_user(first_name, last_name, phone_number)
            if not user:
                return jsonify({"success": False, "error": "User not found. Please check your details."}), 400

            verification_response = send_verification(verification_type, user)
            return jsonify({"success": True, "user_id": user.id, **verification_response})

        # Reset password after successful OTP or security question validation
        elif action_type == 'reset_password':
            user_id = request.form.get('user_id')
            verification_type = request.form.get('verification_type')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            user = User.query.get(user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found."}), 400

            # OTP or security question validation
            if verification_type in ['phone', 'email']:
                otp = request.form['otp']
                if not verify_otp(verification_type, otp):
                    return jsonify({"success": False, "error": "Invalid or expired OTP. Please try again."}), 400
            elif verification_type == 'security_question':
                security_answer = request.form.get('security_answer')
                if security_answer.lower() != user.answer.lower():
                    return jsonify({"success": False, "error": "Incorrect answer to the security question."}), 400

            # Password validation
            if new_password != confirm_password:
                return jsonify({"success": False, "error": "Passwords do not match."}), 400
            valid_password, password_message = validate_password_strength(new_password)
            if not valid_password:
                return jsonify({"success": False, "error": password_message}), 400

            hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_pw
            db.session.commit()

            return jsonify({"success": True, "message": "Password reset successfully.", "redirect_url": "/"})

    return render_template('reset_password.html')

# Route to send OTP for password reset verification
@voter_bp.route('/send_reset_otp', methods=['POST'])
def send_reset_otp():
    data = request.get_json()
    phone_number = data.get('phone_number', '')
    email = data.get('email', '')
    national_id = data.get('national_id')
    country_code = data.get('country_code')

    user = User.query.filter_by(national_id=national_id).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 400

    otp = generate_otp()

    # Send OTP via phone or email based on user input
    if phone_number:
        full_phone_number = f"{country_code}{phone_number}"
        send_otp(full_phone_number, otp, method='phone')
    elif email:
        send_otp(email, otp, method='email')
    else:
        return jsonify({"success": False, "message": "No contact method provided"}), 400

    return jsonify({"success": True, "message": "OTP sent successfully"}), 200
