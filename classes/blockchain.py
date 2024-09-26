import hashlib
import json
import random
from time import time
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from .key_management import KeyManager as key_manager
from .validator import Validator


class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.voters = []
        self.voted = set()
        self.key_manager = key_manager()
        self.validators = []

        # Create the genesis block (the first block in the chain)
        self.new_block(previous_hash='1', proof=100)

    def add_validator(self, validator):
        self.validators.append(validator)

    def choose_validator(self):
        total_stake = sum(validator.stake for validator in self.validators)
        choice = random.uniform(0, total_stake)
        current = 0
        for validator in self.validators:
            current += validator.stake
            if current > choice:
                return validator

    def add_block(self, transactions):
        # Ensure all transactions are dictionaries
        formatted_transactions = []
        for transaction in transactions:
            voter, candidate = transaction.split(": ")
            formatted_transactions.append({
                'sender': voter.strip(),
                'recipient': candidate.strip(),
                'amount': 1
            })

        previous_hash = self.chain[-1]['hash'] if self.chain else '0'
        validator = self.choose_validator()
        new_block = validator.create_block(formatted_transactions, previous_hash)
        self.chain.append(new_block)

    def is_valid_chain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block['previous_hash'] != previous_block['hash']:
                return False

            block_data = {
                'index': current_block['index'],
                'transaction': current_block['transaction'],
                'previous_hash': current_block['previous_hash'],
                'timestamp': current_block['timestamp'],
                'validator': current_block['validator'],
                'proof': current_block['proof']
            }
            if current_block['hash'] != Validator.hash_block(block_data):
                return False
        return True

    def register_voter(self, public_key):
        self.voters.append(public_key)
        # Store the registration on the blockchain (e.g., as a transaction)
        self.new_transaction(sender='system', recipient=public_key.export_key().hex(), amount=0)

    def verify_vote(self, public_key, vote_data):
        public_key_hash = SHA256.new(public_key.export_key()).hexdigest()

        if public_key_hash in self.voted:
            # Voter has already voted
            return False

        h = SHA256.new(vote_data['vote'].encode('utf-8'))
        signature = bytes.fromhex(vote_data['signature'])
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            self.voted.add(public_key_hash)
            return True
        except (ValueError, TypeError):
            # Invalid Signature
            return False

    def cast_vote(self, public_key, vote_data):
        if self.verify_vote(public_key, vote_data):
            vote = vote_data['vote']
            candidate = vote.split()[-1]
            self.new_transaction(sender=public_key.export_key().hex(), recipient=candidate, amount=1)
            return True
        else:
            # Vote rejected
            return False

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: <int> The proof given by the Proof of Work algorithm
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': [transaction for transaction in self.current_transactions if isinstance(transaction, dict)],
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }

        # Hash the block and add the 'hash' key
        block['hash'] = self.hash(block)

        # Reset the current list of transaction
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: <str> Address of the Sender
        :param recipient: <str> Address of the Recipient
        :param amount: <int> Amount
        :return: <int> The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """
        # We must make sure that the dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        # Returns the last Block in the chain
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        """
        Simple Proof of work algorithm:
        - Find a number p' such that hash(pp') contains leading 4 zeroes
        - p is the previous proof, and p' is the new proof
        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Validates the proof: Does hash(last_proof,proof) contains 4 leading zeroes?
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :return: <bool> True if correct, False if not
        """
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == '0000'

    def tally_votes(self):
        votes_count = {}
        for block in self.chain:
            for transaction in block['transactions']:
                print("transaction:", transaction)
                candidate = transaction['recipient']
                if candidate in votes_count:
                    votes_count[candidate] += 1
                else:
                    votes_count[candidate] = 1
        return votes_count

    def declare_winner(self):
        votes_count = self.tally_votes()
        if votes_count:
            # Check for tie
            self.check_for_tie(votes_count)
            winner = max(votes_count, key=votes_count.get)
            return winner, votes_count[winner]
        else:
            return None, 0

    def check_for_tie(self):
        votes_count = self.tally_votes()
        max_votes = max(votes_count.values())

        tie_candidates = [candidate for candidate, votes in votes_count.items() if votes == max_votes]

        if len(tie_candidates) > 1:
            return True, tie_candidates
        else:
            return False, tie_candidates[0]