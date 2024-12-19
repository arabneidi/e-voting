from twilio.rest import Client
from flask import current_app

def get_twilio_client():
    """
    Initializes and returns a Twilio Client using credentials from the Flask app configuration.
    """
    account_sid = current_app.config['TWILIO_ACCOUNT_SID']
    auth_token = current_app.config['TWILIO_AUTH_TOKEN']
    return Client(account_sid, auth_token)

def send_sms(phone_number, message):
    """
    Sends an SMS to the specified phone number.

    Parameters:
    - phone_number: The recipient's phone number
    - message: The content of the SMS
    """
    try:
        client = get_twilio_client()
        twilio_phone_number = current_app.config['TWILIO_PHONE_NUMBER']
        client.messages.create(
            body=message,
            from_=twilio_phone_number,
            to=phone_number
        )
        print(f"SMS sent to {phone_number}")
    except Exception as e:
        print(f"Failed to send SMS: {e}")
