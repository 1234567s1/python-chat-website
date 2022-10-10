import smtplib
from email.message import EmailMessage
import os


def send_verification(receiver, code):
    email = os.environ.get('my_email')
    password = os.environ.get('python_app_pass')
    msg = EmailMessage()
    msg['Subject'] = 'Verification Email'
    msg['From'] = email
    msg['To'] = receiver
    msg.set_content(f'Your verification code is {code}')

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(email, password)

        smtp.send_message(msg)
