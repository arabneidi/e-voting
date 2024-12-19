# Import necessary utilities and libraries
from utils.file_utils import allowed_file  # Checks if file extension is allowed
from utils.election_data_utils import load_election_data, parse_election_data  # Loads and parses election data
import pandas as pd
from flask import Blueprint, request, session, flash, redirect, url_for, render_template, jsonify, current_app
from datetime import datetime, timezone
from werkzeug.utils import secure_filename  # Secures uploaded filenames
from models import Settings, Admin, Result, User, Vote  # Import database models
import os
from extensions import db
import bcrypt  # Library for hashing passwords
import pyotp  # Library for generating TOTP (time-based one-time passwords)
import csv
import glob  # Used for file pattern matching
from utils.twilio_utils import send_sms
from utils.email_utils import send_email
from utils.otp_utils import generate_otp
from utils.ocr_utils import extract_id_card_number  # Extracts information from an ID card

# Define a new Flask blueprint for admin routes
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/logout', methods=['POST'])
def admin_logout():
    # Logs out the admin by clearing the session and redirecting to the login page
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin.admin_login'))

@admin_bp.route('/settings', methods=['GET', 'POST'])
def admin_settings():
    # If admin is not logged in, redirect to login
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin.admin_login'))

    # Fetch existing settings from the database
    settings = Settings.query.first()
    provinces, territories, file_uploaded = [], [], False

    if request.method == 'POST':
        # Process file upload for election data
        if 'upload_file' in request.form and 'election_file' in request.files:
            file = request.files['election_file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                try:
                    # Parse and load election data from the uploaded file
                    data = parse_election_data(filepath)
                    provinces = data['provinces']
                    territories = data['territories']
                    flash('Election data uploaded and processed successfully!', 'success')
                    file_uploaded = True
                except ValueError as e:
                    flash(f'Error processing file: {str(e)}', 'danger')
                    file_uploaded = False
            else:
                flash('Invalid file type. Please upload a valid Excel file.', 'danger')

        # Save election settings from form input
        if 'save_settings' in request.form:
            election_type = request.form.get('election_type')
            election_name = request.form.get('election_name')
            start_time = datetime.strptime(request.form.get('start_time'), '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(request.form.get('end_time'), '%Y-%m-%dT%H:%M')
            extend_time = int(request.form.get('extend_time'))

            # Update or add new settings
            if settings:
                settings.election_type = election_type
                settings.election_name = election_name
                settings.start_time = start_time
                settings.end_time = end_time
                settings.extend_time = extend_time
            else:
                settings = Settings(
                    election_type=election_type,
                    election_name=election_name,
                    start_time=start_time,
                    end_time=end_time,
                    extend_time=extend_time
                )
                db.session.add(settings)

            db.session.commit()
            flash('Election settings saved successfully!', 'success')

    return render_template('admin_settings.html', settings=settings, provinces=provinces, territories=territories, file_uploaded=file_uploaded)

@admin_bp.route('/upload_election_data', methods=['GET', 'POST'])
def upload_election_data():
    # Ensure admin is logged in
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        # Validate that a file has been uploaded
        if 'file' not in request.files:
            flash('No file uploaded.', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

            # Load the election data from Excel sheets
            election_data = pd.read_excel(os.path.join(current_app.config['UPLOAD_FOLDER'], filename), sheet_name=None)
            federal_data, provincial_data, territorial_data = election_data['Federal'], election_data['Provincial'], election_data['Territorial']

            flash('Election data uploaded successfully.', 'success')
            return redirect(url_for('settings'))

    return render_template('upload_election_data.html')

@admin_bp.route('/upload_excel', methods=['POST'])
def upload_excel():
    # Upload an Excel file with election data
    if 'election_file' not in request.files:
        return jsonify({"success": False, "message": "No file part"})

    file = request.files['election_file']
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"})

    if file and allowed_file(file.filename):
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)

        try:
            load_election_data(filepath)
            return jsonify({"success": True, "message": "Election data loaded successfully"})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    return jsonify({"success": False, "message": "Invalid file format"})

@admin_bp.route('/', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        # Validate admin credentials and handle login
        username, password = request.form.get('username'), request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if not admin:
            flash('Admin user not found', 'danger')
            return render_template('admin_login.html', show_totp=False, username=username)

        if not bcrypt.checkpw(password.encode('utf-8'), admin.password.encode('utf-8')):
            flash('Invalid password', 'danger')
            return render_template('admin_login.html', show_totp=False, username=username)

        if admin.totp_secret:
            session['admin_logged_in_without_totp'] = True
            session['admin_id'] = admin.id
            flash('Please enter your Google Authenticator code to continue', 'info')
            return render_template('admin_login.html', show_totp=True, username=username)
        else:
            session['admin_logged_in'] = True
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            flash('Login successful', 'success')
            return redirect(url_for('admin.admin_dashboard'))

    return render_template('admin_login.html', show_totp=False)

@admin_bp.route('/verify_totp_login', methods=['POST'])
def verify_totp_login():
    admin_id = session.get('admin_id')
    if not admin_id:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('admin.admin_login'))

    # Validate the TOTP code provided by the admin
    totp_code = request.form.get('totp_code')
    admin = Admin.query.get(admin_id)

    if not admin.totp_secret:
        flash('TOTP not set for this admin. Please set it up.', 'danger')
        return redirect(url_for('admin.admin_change_password'))

    totp = pyotp.TOTP(admin.totp_secret)
    if not totp.verify(totp_code):
        flash('Invalid Google Authenticator code', 'danger')
        return render_template('admin_login.html', show_totp=True, username=admin.username)

    session['admin_logged_in'] = True
    session.pop('admin_logged_in_without_totp', None)
    flash('Login successful', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/forget_password', methods=['GET', 'POST'])
def admin_forget_password():
    if request.method == 'POST':
        username = request.form['username']
        totp_code = request.form['totp_code']

        admin = Admin.query.filter_by(username=username).first()
        if not admin:
            flash('Admin not found', 'danger')
            return redirect(url_for('admin.admin_forget_password'))

        # Validate TOTP code for password reset
        totp = pyotp.TOTP(admin.totp_secret)
        if not totp.verify(totp_code):
            flash('Invalid Google Authenticator code.', 'danger')
            return redirect(url_for('admin.admin_forget_password'))

        return redirect(url_for('admin.admin_reset_password', username=username))

    return render_template('admin_forget_password.html')

@admin_bp.route('/forgot_password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        # Admin password reset with TOTP verification
        google_auth_code = request.form.get('google_auth_code')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            flash('Admin user not found', 'danger')
            return redirect(url_for('admin.admin_forgot_password'))

        totp = pyotp.TOTP(admin.totp_secret)
        if not totp.verify(google_auth_code):
            flash('Invalid Google Authenticator code', 'danger')
            return redirect(url_for('admin.admin_forgot_password'))

        # Password validation
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('admin.admin_forgot_password'))
        if len(new_password) < 8 or not any(char.isdigit() for char in new_password) or not any(char.isupper() for char in new_password):
            flash('New password must be at least 8 characters, with at least one uppercase letter and one number.', 'danger')
            return redirect(url_for('admin.admin_forgot_password'))

        # Update the password in the database
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        admin.password = hashed_password
        db.session.commit()

        flash('Password reset successfully!', 'success')
        return redirect(url_for('admin.admin_login'))

    return render_template('admin_forgot_password.html')

@admin_bp.route('/change_password', methods=['GET', 'POST'])
def admin_change_password():
    # Checks if the admin is logged in; if not, redirects to login page
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin.admin_login'))

    admin_id = session.get('admin_id')
    if not admin_id:
        flash('Session error. Please log in again.', 'danger')
        return redirect(url_for('admin.admin_login'))

    # Fetch the admin's current information from the database
    admin = Admin.query.get(admin_id)

    if request.method == 'POST':
        # Retrieve current and new password details from form input
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Verify the current password matches the database record
        if not bcrypt.checkpw(current_password.encode('utf-8'), admin.password.encode('utf-8')):
            flash('Current password is incorrect', 'danger')
            return render_template('admin_change_password.html')

        # Check that new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return render_template('admin_change_password.html')

        # Ensure the new password meets strength requirements
        if len(new_password) < 8 or not any(char.isdigit() for char in new_password) or not any(char.isupper() for char in new_password):
            flash('New password must be at least 8 characters, with at least one uppercase letter and one number.', 'danger')
            return render_template('admin_change_password.html')

        # Update and hash the new password, and save it in the database
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        admin.password = hashed_password

        # Prompt to set up Google Authenticator if it hasn't been configured yet
        if not admin.totp_secret:
            totp_secret = pyotp.random_base32()
            admin.totp_secret = totp_secret
            db.session.commit()

            # Generate a QR code URI for Google Authenticator setup
            totp = pyotp.TOTP(totp_secret)
            qr_code_uri = totp.provisioning_uri(name=admin.username, issuer_name="E-Voting")

            flash('Password changed successfully! Please scan the QR code with Google Authenticator.', 'success')
            return render_template('setup_google_auth.html', qr_code_uri=qr_code_uri)

        # Commit the password change if TOTP setup is not needed
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('admin_change_password.html')

@admin_bp.route('/setup_google_auth', methods=['GET', 'POST'])
def setup_google_auth():
    # Ensures admin is logged in to proceed with Google Authenticator setup
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin.admin_login'))

    admin_id = session['admin_id']
    admin = Admin.query.get(admin_id)

    # Checks if Google Authenticator has already been set up
    if admin.totp_secret:
        flash('Google Authenticator is already set up.', 'info')
        return redirect(url_for('admin.admin_dashboard'))

    if request.method == 'POST':
        # Generate a new TOTP secret and save it in the database
        totp_secret = pyotp.random_base32()
        admin.totp_secret = totp_secret
        db.session.commit()

        # Generate QR code URI for Google Authenticator setup
        totp = pyotp.TOTP(totp_secret)
        qr_code_uri = totp.provisioning_uri(name=admin.username, issuer_name="E-Voting")

        flash('Please scan the QR code with Google Authenticator and enter the code to complete setup.', 'success')
        return render_template('setup_google_auth.html', qr_code_uri=qr_code_uri)

    return render_template('setup_google_auth.html')

@admin_bp.route('/verify_totp', methods=['POST'])
def verify_totp():
    # Verify that the admin session exists
    if 'admin_id' not in session:
        return redirect(url_for('admin.admin_login'))

    admin_id = session['admin_id']
    admin = Admin.query.get(admin_id)

    if not admin:
        flash('Admin not found. Please log in again.', 'danger')
        return redirect(url_for('admin.admin_login'))

    # Verifies the provided TOTP code using the stored secret
    totp_code = request.form.get('totp_code')
    if admin.totp_secret:
        totp = pyotp.TOTP(admin.totp_secret)
        if totp.verify(totp_code):
            session['admin_logged_in'] = True
            session.pop('admin_logged_in_without_totp', None)
            flash('Google Authenticator successfully set!', 'success')
            return redirect(url_for('admin.admin_dashboard'))
        else:
            flash('Invalid Google Authenticator code. Please try again.', 'danger')
            return render_template('setup_google_auth.html', qr_code_uri=admin.totp_secret)

    flash('Authenticator setup failed. Please try again.', 'danger')
    return redirect(url_for('admin.admin_login'))

@admin_bp.route('/result')
def show_result():
    # Searches for the latest voting results CSV file
    file_pattern = "/home/ec2-user/voting/exports/voting_results_*.csv"
    files = sorted(glob.glob(file_pattern), key=os.path.getmtime, reverse=True)

    if files:
        # Serve the latest results file and display it in a table
        latest_file = files[0]
        table_data = []
        with open(latest_file, "r") as file:
            reader = csv.reader(file)
            headers = next(reader)
            for row in reader:
                table_data.append(row)

        return render_template("result.html", headers=headers, table_data=table_data)

    return "Results file not found. Please check back later.", 404

@admin_bp.route('/export_result', methods=['POST'])
def export_result():
    # Creates an export directory and saves voting results in a CSV file
    export_directory = os.path.join(os.getcwd(), 'exports')
    os.makedirs(export_directory, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_path = os.path.join(export_directory, f'voting_results_{timestamp}.csv')

    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Number', 'Reference Code', 'Candidate Name', 'Candidate Code'])

        # Write all results to the CSV
        results = Result.query.all()
        for i, result in enumerate(results, start=1):
            writer.writerow([i, result.reference_code, result.candidate_name, result.candidate_code])

    return jsonify({"message": f"CSV file generated and saved at {file_path}"})

@admin_bp.route('/dashboard')
def admin_dashboard():
    # Checks if admin is logged in; if not, redirects to the login page
    if 'admin_logged_in' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('admin.admin_login'))

    admin_id = session.get('admin_id')
    if not admin_id:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('admin.admin_login'))

    admin = Admin.query.get(admin_id)
    if not admin:
        flash('Admin not found. Please log in again.', 'danger')
        session.pop('admin_logged_in', None)
        session.pop('admin_id', None)
        return redirect(url_for('admin.admin_login'))

    if not admin.totp_secret:
        flash('Please change your password and set up Google Authenticator.', 'warning')
        return redirect(url_for('admin.admin_change_password'))

    return render_template('admin_dashboard.html', admin=admin)

@admin_bp.route('/monitoring')
def monitoring():
    # Displays total votes, users, and voter information
    total_votes = db.session.query(Vote).count()
    total_users = db.session.query(User).count()
    voters = db.session.query(User.id, User.first_name, User.last_name).all()

    return render_template('monitoring.html', total_votes=total_votes, total_users=total_users, voters=voters)

@admin_bp.route('/voter_info/<int:user_id>', methods=['GET'])
def voter_info(user_id):
    # Fetches information for a specific voter
    user = db.session.query(User).filter_by(id=user_id).first()
    if not user:
        return jsonify({"error": "Voter not found"}), 404

    bank_info = user.bank
    if not bank_info:
        return jsonify({"error": "No associated bank information found"}), 404

    voter_info = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "age": bank_info.age if bank_info.age is not None else "N/A"
    }

    return jsonify(voter_info)

@admin_bp.route('/send_otp_phone', methods=['POST'])
def send_otp_phone():
    # Sends OTP to the admin's phone
    try:
        data = request.get_json()
        full_phone_number = data.get('phone_number')

        if not full_phone_number:
            return jsonify({'success': False, 'message': 'Phone number is required.'}), 400

        otp = generate_otp()
        send_sms(full_phone_number, f"Your OTP code is {otp}")
        session['otp_phone'] = otp
        session['otp_generation_time'] = datetime.now(timezone.utc).isoformat()

        return jsonify({"success": True, 'message': 'OTP sent successfully to phone.'})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Internal server error.'}), 500

@admin_bp.route('/send_otp_email', methods=['POST'])
def send_otp_email():
    # Sends OTP to the admin's email
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required.'}), 400

        otp = generate_otp()
        send_email(email, "Your OTP Code", f"Your OTP is: {otp}")
        session['otp_email'] = otp
        session['otp_generation_time_email'] = datetime.now(timezone.utc).isoformat()

        return jsonify({'success': True, 'message': 'OTP sent successfully to email.'})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to send OTP.'}), 500

@admin_bp.route('/extract_id_card', methods=['POST'])
def extract_id_card():
    # Extracts the ID card number from an uploaded image
    if 'id_card' not in request.files:
        return jsonify({'success': False, 'message': 'ID card file is required.'}), 400

    id_card_file = request.files['id_card']
    try:
        passport_number = extract_id_card_number(id_card_file)
        return jsonify({'success': True, 'passport_number': passport_number})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred while extracting the ID card number.'}), 500

