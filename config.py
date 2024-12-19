import os
from datetime import timedelta  # Import for session lifetime settings

class Config:
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY')  # Secret key for Flask sessions and cookies

    # reCAPTCHA configuration
    RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')  # reCAPTCHA secret key retrieved from environment variable

    # File upload settings
    UPLOAD_FOLDER = 'D:/aws voting/backend/uploads'  # Folder where uploaded files will be stored
    ALLOWED_EXTENSIONS = {'xls', 'xlsx'}  # Allowed file types for uploads

    ELECTION_DATA_PATH = 'election data/election_data.xlsx'  # Path for election data file

    DIALOGFLOW_PROJECT_ID = os.getenv('DIALOGFLOW_PROJECT_ID')  # Dialogflow project ID
    # Google Vision credentials
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "D:/aws voting/backend/vision-key.json"  # Path to Google Vision credentials

    # Database configuration
    SQLALCHEMY_DATABASE_URI = "sqlite:///voting_system.db"  # Database URI retrieved from environment variable
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable modification tracking to save resources
    SQLALCHEMY_POOL_SIZE = 10  # Set connection pool size
    SQLALCHEMY_MAX_OVERFLOW = 20  # Allow overflow connections beyond pool size

    # Email settings for SMTP
    SENDER_EMAIL = os.getenv('SENDER_EMAIL')  # Sender email from environment variable
    SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')  # Sender email password from environment variable
    SMTP_SERVER = 'smtp.gmail.com'  # SMTP server for Gmail
    SMTP_PORT = 587  # Port for SMTP server

    # Twilio account credentials
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')  # Twilio Account SID from environment variable
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')  # Twilio Auth Token from environment variable
    TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')  # Twilio phone number from environment variable

    # CORS configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS')  # Allowed origins for CORS, loaded from environment

    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_TYPE = 'filesystem'  # Use local file-based sessions
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_NAME = 'session'
    SESSION_COOKIE_SECURE = False  # Disable HTTPS requirement for local testing
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


