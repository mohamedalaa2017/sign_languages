# utils.py

from django.core.mail import send_mail

def send_reset_email(user, reset_url):
    subject = 'Password Reset Request'
    message = f'Click the following link to reset your password: {reset_url}'
    from_email = 'your@example.com'  # Replace with your sender email
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)
