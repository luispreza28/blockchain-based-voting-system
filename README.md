# Voting Application

## Introduction
This Voting Application enables users to securely register as voters, cast their votes, and view election results. Built on a blockchain framework, the application ensures the integrity and transparency of the voting process. Utilizing RSA encryption for securing user data and votes, the app also implements a two-factor authentication (2FA) mechanism to enhance security.

## Installation

## Prerequisites
Make sure you have Python 3.x installed on your machine.

## Step 1: Clone the Repository

```git clone <repository_url> cd voting_application```

## Step 2: Create a Virtual Environment

```python -m venv venv source venv/bin/activate```  # On Windows use `venv\Scripts\activate`

## Step 3: Install Required Packages
Install the necessary Python packages using pip:

``` pip install Flask Flask-SQLAlchemy Flask-Mail python-dotenv pyotp pycryptodome ```

## Step 4: Set Up Environment Variables
Create a .env file in the root of the project and add the following:

- SECRET_KEY=<your_secret_key>
- MAIL_USERNAME=<your_email>
- MAIL_PASSWORD=<your_email_password>

## Step 5: Database Setup
The application uses SQLite for storing user and voting data. The database will be created automatically if it doesn't already exist. To initialize the database, run:

```python -c "from your_application import create_app; app = create_app(); with app.app_context(): from your_application.models import db; db.create_all()"```

## Key Features
### Voter Registration
Users can register by providing a username, email, and password.
Upon registration, an RSA key pair is generated. The public key is registered on the blockchain, while the private key can be downloaded securely.

### Vote Casting
Voters log in using their credentials and an OTP sent to their email.
Users can select a candidate and sign their vote using their RSA private key.
The application validates the user's keys and stores the vote securely on the blockchain.

### Results and Poll Reset
After the poll is closed, results can be declared based on the votes recorded in the blockchain.
The system handles ties and declares winners accordingly.
Once results are declared, the voting data is reset for the next election cycle.

# Blueprints and Routes
## The application is structured using Flask blueprints. Below are some of the primary routes:

### Authentication Routes
- /auth/login: User login with OTP verification.
- /auth/logout: Logout the current user.
- /auth/regenerate_keys: Regenerate RSA keys with OTP verification.

### Voting Routes
- /: Home page, showing user authentication status.
- /register_voter: Voter registration page.
- /cast_vote: Page for casting votes, available only to logged-in users who haven't voted.
- /results: View the election results.
- /add_candidate: Endpoint for adding candidates, accessible to admins only.

## Admin Functionality
### Admins have special privileges:

- /give_admin/<username>: Grant admin rights to a user.
- /end_poll: Close the voting and reset for the next poll.

## Error Handling and Flash Messages
- The application provides user feedback through flash messages, which notify users of various events, such as:

## Invalid login credentials.
- OTP verification issues.
- Successful actions like voter registration and vote casting.

## How to Run the Application
### To run the application, set the necessary environment variables and use the following commands:

```export FLASK_APP=your_application```  # Replace with your application's entry point
```export FLASK_ENV=development```
```flask run```
Access the application in your web browser at http://127.0.0.1:5000.

## Conclusion
This Voting Application demonstrates the use of blockchain technology for secure voting. With enhanced security measures such as RSA encryption and OTP verification, it aims to provide a trustworthy platform for conducting elections.

For further questions or contributions, feel free to open an issue or submit a pull request.
