import tempfile
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from flask import render_template, request, Blueprint, jsonify, url_for, send_file, flash, redirect
from flask_login import current_user
from classes.blockchain import Blockchain
from classes.key_management import KeyManager
from .models import Candidate, db, User
from utils import utils


views = Blueprint('views', __name__)

blockchain = Blockchain()
key_manager = KeyManager()


# Route for home
@views.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@views.route('/register_voter', methods=['POST', 'GET'])
def register_voter():
    if request.method == 'POST':
        # Get form information
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        # Check if passwords match
        if password != confirm_password:
            return jsonify({"message": "Passwords do not match"}), 400

        # Create the user
        new_user = User(username=username, email=email)
        new_user.set_password(password)

        # Save the public key  in the blockchain
        try:
            # Generate a new RSA key pair
            private_key_bytes, public_key_bytes = utils.generate_key_pair()

            # Import public key
            public_key = RSA.import_key(public_key_bytes)

            # Register voter
            blockchain.register_voter(public_key)

            # Add user and save session
            db.session.add(new_user)
            db.session.commit()

            # Generate private key path
            private_key_path = utils.save_key_to_tempfile(private_key_bytes)

            # Generate public key path
            public_key_path = utils.save_key_to_tempfile(public_key_bytes)

            # Generate downloadable links for private and public keys
            download_link_private, download_link_public = utils.create_download_links(private_key_path, public_key_path)

            # Return response with download link
            return render_template('register_voter_success.html', download_link_private=download_link_private, download_link_public=download_link_public)
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': f'Error registering voter: {str(e)}'})

    return render_template('register_voter.html')


@views.route('/cast_vote', methods=['POST', 'GET'])
def cast_vote():
    if request.method == 'POST':
        # Ensure user is logged in and has not voted
        if not current_user.is_authenticated or current_user.has_voted:
            return jsonify({'message': 'You need to be logged in and not have voted to vote'}), 403

        # Get form information
        candidate_id = request.form.get('candidate')
        public_key_str = request.form.get('public_key')
        private_key_str = request.form.get('private_key')

        # Check if information from form is valid
        if not candidate_id or not public_key_str or not private_key_str:
            return jsonify({'message': 'Candidate, private key, and public key are required'})

        try:
            # Clean and decode the submitted public and private keys before importing them
            # This ensures proper formatting and removes any unwanted characters
            public_key = RSA.import_key(utils.clean_and_decode_key(public_key_str, 'public'))
            private_key = RSA.import_key(utils.clean_and_decode_key(private_key_str, 'private'))

            # Hash vote
            vote_hash = SHA256.new(candidate_id.encode('utf-8'))

            # Get signature
            signature = pkcs1_15.new(private_key).sign(vote_hash)

            # Store candidate id and signature
            vote_data = {'vote': candidate_id, 'signature': signature.hex()}

            # Cast the vote using the blockchain method
            if blockchain.cast_vote(public_key, vote_data):

                # Get candidate
                candidate = Candidate.query.get(candidate_id)

                # Check if candidate exists
                if candidate:

                    # Increment candidate vote
                    candidate.votes += 1

                    # Set current user to has voted
                    current_user.has_voted = True

                    # Save session
                    db.session.commit()

                    return render_template('vote_success.html')
                else:
                    return jsonify({'message': 'Candidate not found'}), 404
            flash("Vote cast was unsuccessful", 'error')
        except ValueError as e:
            return jsonify({'message': f'Invalid public key: {str(e)}'}), 400
        return redirect(url_for('views.index'))

    candidates = Candidate.query.all()
    return render_template('cast_vote.html', candidates=candidates)


@views.route('/results', methods=['GET'])
def results():
    if request.method == 'GET':
        # Get winner and votes
        winner, votes = blockchain.declare_winner()

        return render_template('results.html', winner=winner, votes=votes)


@views.route('/candidates', methods=['GET'])
def list_candidates():
    if request.method == 'GET':
        # Get candidates
        candidates = Candidate.query.all()

        return render_template('candidates.html', candidates=candidates)


@views.route('/add_candidate', methods=['POST'])
def add_candidate():
    # Get form information
    name = request.form.get('name')
    party = request.form.get('party', '')
    description = request.form.get('description', '')

    # Create a new candidate
    new_candidate = Candidate(name=name, party=party, description=description)

    # Add new cadidate
    db.session.add(new_candidate)

    # Save session
    db.session.commit()

    return jsonify({'message': f'Candidate {name} added successfully'}), 201


@views.route('/download/<filename>')
def download_private_key(filename):
    # Create private file path
    file_path = os.path.join(tempfile.gettempdir(), filename)

    try:
        # Send private file
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'message': 'File not found'}), 404


@views.route('/download_public_key/<filename>')
def download_public_key(filename):
    # Create public file path
    file_path = os.path.join(tempfile.gettempdir(), filename)

    try:
        # Send public file
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'message': 'File not found'}), 404


@views.route('/give_admin/<username>')
def give_admin(username):
    try:
        utils.give_admin_privileges(username)
        return jsonify({'message': f'Admin privileges given to {username}'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@views.route('/create_candidate', methods=['POST', 'GET'])
def create_candidate():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        party = request.form.get('party')
        description = request.form.get('description')

        # Validate that name and party are provided
        if not name or not party:
            flash("Name and party are required.", 'error')
            return redirect(url_for('views.create_candidate'))

        # Create a new Candidate object
        new_candidate = Candidate(name=name, party=party, description=description)

        try:
            # Add the candidate to the database
            db.session.add(new_candidate)

            # Save session
            db.session.commit()

            flash("Candidate created successfully!", 'success')
            return redirect(url_for('views.create_candidate'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating candidate: {str(e)}", 'error')
            return redirect(url_for('views.create_candidate'))

    return render_template('create_candidate.html')


@views.route('/end_poll', methods=['POST'])
def end_poll():
    # Check if current user has admin privileges
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized access"})

    # Get all candidates and their votes
    candidates = Candidate.query.all()

    # Find the candidate(s) with the highest number of votes
    max_votes = max(candidate.votes or 0 for candidate in candidates)

    # Find and store winner
    winners = [candidate for candidate in candidates if candidate.votes == max_votes]

    # Determine if it's a tie or a signale winner
    if len(winners) > 1:
        result_message = "It's a tie between" + ', '.join([winner.name for winner in winners])
    else:
        result_message = f"The winner is: {winners[0].name}"

    # Render the results page with the vote counts
    rendered_template = render_template('results.html', candidates=candidates, result_message=result_message)

    # Reset votes for all candidates for the next poll
    for candidate in candidates:
        candidate.votes = 0
    db.session.commit()

    # Reset user voting status for the next poll
    users = User.query.all()
    for user in users:
        user.has_voted = False
    db.session.commit()

    # Reset the blockchain for the next poll cycle
    # This clears all votes, retaining only the genesis block, and resets current transactions
    blockchain.voted.clear()
    blockchain.chain = [blockchain.chain[0]]
    blockchain.current_transaction = []

    return rendered_template
