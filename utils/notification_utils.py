from utils.twilio_utils import send_sms
from utils.email_utils import send_email

def send_vote_confirmation(user, reference_code):
    """Send vote confirmation to user's phone and email if verified."""
    if user.phone_verified:
        try:
            send_sms(user.phone_number, f"Your vote has been cast successfully! Reference Code: {reference_code}")
            print(f"Vote confirmation sent to phone: {user.phone_number}")
        except Exception as e:
            print(f"Failed to send SMS: {e}")

    if user.email_verified:
        try:
            send_email(user.email, "Vote Confirmation", f"Your vote has been cast successfully! Reference Code: {reference_code}")
            print(f"Vote confirmation sent to email: {user.email}")
        except Exception as e:
            print(f"Failed to send email: {e}")
