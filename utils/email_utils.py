import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app


def send_email(to_email, subject, body):
    """
    Sends an email using SMTP settings configured in the Flask application.

    Parameters:
    - to_email: Recipient email address
    - subject: Subject of the email
    - body: Text content of the email
    """
    sender_email = current_app.config['SENDER_EMAIL']
    sender_password = current_app.config['SENDER_PASSWORD']
    smtp_server = current_app.config['SMTP_SERVER']
    smtp_port = current_app.config['SMTP_PORT']

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Set up the SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Enable encryption for the connection
        server.login(sender_email, sender_password)
        text = msg.as_string()

        # Send the email
        server.sendmail(sender_email, to_email, text)
        server.quit()
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
