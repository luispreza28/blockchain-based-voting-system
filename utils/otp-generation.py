import pyotp
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


def generate_otp(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()


def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)


def register_voter(blockchain, public_key, password, otp_secret):
    # Step 1: Encrypt and store the private key with the password
    private_key_bytes = public_key.export_key()
    encrypted_private_key = blockchain.key_manager.encrypt_private_key(private_key_bytes, password)

    # Store encrypted private and public key
    with open('../private_key.pem', 'wb') as f:
        f.write(encrypted_private_key)
    with open('../public_key.pem', 'wb') as f:
        f.write(public_key.export_key())

    # Step 2: Verify OTP entered by the user
    user_otp = input("Enter the OTP sent to your registered device: ")
    if verify_otp(otp_secret, user_otp):
        blockchain.register_voter(public_key)
        print("Voter registration successful")
    else:
        print("OTP verficiation failed. Registration unsuccessful.")


# During voting:
def cast_vote(blockchain, public_key, vote, password, otp_secret):
    # Step 1: Verify OTP for voting
    otp = generate_otp(otp_secret)
    print(f"Your OTP for voting is: {otp}")

    user_otp = input("Enter the OTP sent to your registered device: ")
    if verify_otp(otp_secret, user_otp):
        # Step 2: Decrypt the private key using the password
        with open('../private_key.pem', 'rb') as f:
            encrypted_private_key = f.read()
            private_key = blockchain.key_manager.decrypt_private_key(encrypted_private_key, password)

        # Step 3: Sign the vote with the private key
        h = SHA256.new(vote.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(h)

        # Step 4: Cast the vote
        vote_data = {
            'vote': vote,
            'signature': signature.hex()
        }

        if blockchain.cast_vote(public_key, vote_data):
            print("Vote successfully cast and recorded on the blockchain")
        else:
            print("Vote failed verification and was not recorded")
    else:
        print("OTP verification failed. Vote not cast.")