from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import os
from dotenv import load_dotenv


db = SQLAlchemy()
load_dotenv()
mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Email configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)

    # Import models after app and db are initialized to avoid circular imports
    from .models import User, Candidate

    # Only create the database if it doesn't exist
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    if not os.path.exists(db_path):
        with app.app_context():
            db.create_all()
        print(f"Database created at {db_path}")
    else:
        print(f"Database already exists at {db_path}")

    from .views import views
    from .auth import auth as auth_blueprint

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    return app
