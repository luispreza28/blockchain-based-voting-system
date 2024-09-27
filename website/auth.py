import time
from flask import request, redirect, url_for, flash, Blueprint, render_template, session, jsonify
from flask_login import login_user, logout_user
from .models import User
import pyotp
from utils import utils


auth = Blueprint('auth', __name__)
DEFAULT_EMAIL = 'testingbvs96@gmail.com'


@auth.route('/regenerate_keys_success', methods=['GET'])
def regenerate_keys_success():
    # Create private and public links
    download_link_private = request.args.get('download_link_private')
    download_link_public = request.args.get('download_link_public')
    return render_template('regenerate_keys_success.html', download_link_private=download_link_private, download_link_public=download_link_public)


@auth.route('/regenerate_keys', methods=['POST', 'GET'])
def regenerate_keys():
    # Check if OTP was verified
    if not session.get('otp_verified'):
        flash("You need to verify OTP before regenerating keys.", 'error')
        return redirect(url_for('auth.generate_otp', purpose='regenerate_keys'))

    if request.method == 'POST':
        try:
            # Get download links
            download_link_private, download_link_public = utils.regenerate_keys()

            # Clear the OTP verification after successful key regeneration
            session.pop('otp_verified', None)  # Reset after key regeneration

            flash('Your keys have been regenerated. Please download your new keys', 'success')
            return redirect(url_for('auth.regenerate_keys_success', download_link_private=download_link_private, download_link_public=download_link_public))
        except Exception as e:
            # Handle potential errors gracefully
            flash(f'An error occurred during key regeneration: {str(e)}', 'error')
            return redirect(url_for('auth.regenerate_keys'))
    return render_template('regenerate_keys.html')


@auth.route('/generate_otp/<purpose>', methods=['GET'])
def generate_otp(purpose):
    # Retrieve the user ID from the session
    user_id = session['otp_user_id']

    # Get the user object
    user = User.query.get(user_id)

    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    # Generate a new OTP using the secret
    otp_secret = session.get('otp_secret')
    totp = pyotp.TOTP(otp_secret)
    otp = totp.now()

    try:
        # Email the user  their OTP
        utils.send_otp(user.email, otp, purpose)
    except Exception as e:
        flash(f"Error sending OTP mail: {str(e)}")
        return jsonify({'message': 'Error in sending OTP mail'})

    # Store OTP and timestamp in the session
    # session['otp'] = otp
    session['otp_timestamp'] = time.time()
    session['otp_purpose'] = purpose

    return redirect(url_for('auth.verify_otp'))


@auth.route('/verify_otp', methods=['POST', 'GET'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')

        # Retrieve stored OTP and check its validity
        otp_secret = session.get('otp_secret')
        otp_timestamp = session.get('otp_timestamp')
        otp_purpose = session.get('otp_purpose')

        # Verify OTP
        totp = pyotp.TOTP(otp_secret)
        is_valid = totp.verify(user_otp, valid_window=1)

        if is_valid:
            session['otp_verified'] = True

            if otp_purpose == 'login':
                # Get user id
                user_id = session.get('otp_user_id')

                # Find User account with user id
                user = User.query.get(user_id)

                if user:
                    # Login user
                    login_user(user)

                    flash("Logged in successfully!", 'success')

                    # Clear OTP data rom session after successful login
                    utils.clear_otp_session()

                    return redirect(url_for('views.index'))
            elif otp_purpose == 'regenerate_keys':
                flash("OTP verified, Proceed to regenerate keys.", 'success')

                # Clear OTP data after key regeneration
                utils.clear_otp_session()

                return redirect(url_for('auth.regenerate_keys'))
        else:
            flash('Invalid or expired OTP. Please try again', 'error')
            return redirect(url_for('auth.generate_otp', purpose=otp_purpose))

    return render_template('verify_otp.html')


@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # Grab information from form
        username = request.form.get('username')
        password = request.form.get('password')

        # Find user account
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Get the OTP secret
            otp_secret = user.get_otp_secret()
            totp = pyotp.TOTP(otp_secret)
            otp = totp.now()

            try:
                # Email user their OTP
                utils.send_otp(user.email, otp, 'login')
            except Exception as e:
                flash(str(e), 'error')
                return redirect(url_for('auth.login'))

            # Store OTP-related data in the session
            session['otp_timestamp'] = time.time()
            session['otp_user_id'] = user.id
            session['otp_purpose'] = 'login'
            session['otp_secret'] = otp_secret

            return redirect(url_for('auth.verify_otp', purpose='login'))

        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('auth.login'))

    return render_template('login.html')


@auth.route('/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
