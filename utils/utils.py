import base64
import os
import tempfile
from flask_mail import Message
from Crypto.PublicKey import RSA
from flask import url_for, flash, session
from website import db, mail
from website.auth import DEFAULT_EMAIL
from website.models import User
from cryptography.hazmat.primitives import serialization


def generate_key_pair():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    private_key_bytes = private_key.export_key()
    public_key_bytes = public_key.export_key()

    return private_key_bytes, public_key_bytes


def give_admin_privileges(username):
    # Finder the user by username
    user = User.query.filter_by(username=username).first()

    if user:
        user.is_admin = True

        db.session.commit()
        print(f"Admin privileges give to {username}")
    else:
        print(f"User {username} not found")


def load_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)


def cleanup_temp_files():
    for file in os.listdir('/path/to/temp/files'):
        file_path = os.path.join('/path/to/temp/files', file)
        if os.path.isfile(file_path) and file.endswith('.pem'):
            os.remove(file_path)


def clean_and_decode_key(key_str, key_type='public'):
    """Helper function to clean and decode a key from a string."""
    key_type_map = {
        'public': ('-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'),
        'private': ('-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----')
    }
    start, end = key_type_map[key_type]
    key_str = key_str.replace(start, "").replace(end, "").replace("\n", "").replace(" ", "")
    key_str += '=' * (4 - len(key_str) % 4)  # Add padding if necessary
    return base64.b64decode(key_str)


def save_key_to_tempfile(key_bytes, suffix='.pem'):
    """Helper function to save key bytes to a temporary file and return the file path."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        temp_file.write(key_bytes)
        return temp_file.name


def create_download_links(private_key_path, public_key_path):
    """Helper function to create download links for private and public keys."""
    download_link_private = url_for('views.download_private_key', filename=os.path.basename(private_key_path), _external=True)
    download_link_public = url_for('views.download_public_key', filename=os.path.basename(public_key_path), _external=True)
    return download_link_private, download_link_public


def regenerate_keys():
    try:
        # Generate a new RSA key pair
        private_key_bytes, public_key_bytes = generate_key_pair()

        # Save keys to temporary files
        private_key_path = save_key_to_tempfile(private_key_bytes)
        public_key_path = save_key_to_tempfile(public_key_bytes)

        # Create download links
        download_link_private = url_for('views.download_private_key', filename=os.path.basename(private_key_path), _external=True)
        download_link_public = url_for('views.download_public_key', filename=os.path.basename(public_key_path), _external=True)

        return download_link_private, download_link_public
    except Exception as e:
        raise e  # Let the caller handle the exception


def send_otp(user_email, otp, purpose):
    try:
        # Determine the email subject based on the purpose
        subject = 'Your OTP for ' + ('login' if purpose == 'login' else 'Key Regeneration')

        # Create and send the OTP email
        msg = Message(subject, sender=DEFAULT_EMAIL, recipients=[user_email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        flash(f"An OTP has been sent to {user_email}. Please check your inbox.", 'info')
    except Exception as e:
        raise Exception(f"Error sending OTP: {str(e)}")


def clear_otp_session():
    session.pop('otp', None)
    session.pop('otp_timestamp', None)
    session.pop('otp_purpose', None)
