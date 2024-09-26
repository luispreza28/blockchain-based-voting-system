import pyotp

from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    is_admin = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(16))
    has_voted = db.Column(db.Boolean, default=False)

    def get_otp_secret(self):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
            db.session.commit()
        return self.otp_secret

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

    def get_id(self):
        return str(self.id)


class Candidate(db.Model):
    __tablename__ = 'Candidates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    party = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    votes = db.Column(db.Integer, default=0)

    def __init__(self, name, party, description=None):
        self.name = name
        self.party = party
        self.description = description

    def __repr__(self):
        return f"<Candidate {self.name}>"
