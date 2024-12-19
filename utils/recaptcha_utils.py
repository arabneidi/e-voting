import requests
from flask import current_app

def verify_recaptcha_v3(recaptcha_token):
    """Verify the reCAPTCHA v3 token with Google."""
    recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': current_app.config['RECAPTCHA_SECRET_KEY'],
        'response': recaptcha_token
    }

    try:
        response = requests.post(recaptcha_verify_url, data=payload)
        result = response.json()

        # Debugging: Print Google's response for verification
        print(f"reCAPTCHA verification result: {result}")

        return result.get('success', False) and result.get('score', 0) >= 0.5
    except Exception as e:
        print(f"Error during reCAPTCHA verification: {e}")
        return False
