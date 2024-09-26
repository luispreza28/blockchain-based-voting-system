import random
import time
import hashlib

class OTPManager:
    def __init__(self):
        # Create variable for storing OTP
        self.otp_store = {}

    def generate_otp(self, user_id, expiration=300):
        # Generate a 6-digit OTP
        otp = str(random.randint(100000, 999999))

        # Set expiration time
        expiration_time = time.time() + expiration

        self.otp_store[user_id] = {
            'otp': otp,
            'expiration_time': expiration_time,
            'used': False
        }
        return otp

    def verify_otp(self, user_id, entered_otp):
        if user_id in self.otp_store:
            otp_data = self.otp_store[user_id]

            # Check if OTP has been used
            if otp_data['used']:
                return False

            # Check if OTP is still valid
            if time.time() < otp_data['expiration_time']:
                if otp_data['otp'] == entered_otp:
                    # Mark OTP as used
                    otp_data['used'] = True
                    return True
                else:
                    return False
            else:
                # OTP expired, remove expired OTP
                del self.otp_store[user_id]
                return False
        # No OTP found for user
        return False

    def cleanup_expired_otp(self):
        current_time = time.time()
        expired_users = [user_id for user_id, (otp, exp_time) in self.otp_store.items() if current_time >= exp_time]
        for user_id in expired_users:
            del self.otp_store[user_id]

    def _get_key(self, user_id, nonce):
        return hashlib.sha256(f"{user_id}-{nonce}".encode()).hexdigest()
