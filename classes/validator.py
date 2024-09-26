import random
import hashlib
import time
import json

class Validator:
    def __init__(self, id, stake):
        self.id = id
        self.stake = stake
        self.reputation = 0
        self.chain = []

    def create_block(self, transaction, previous_hash):
        block_data = {
            'index': len(self.chain) + 1,
            'transactions': transaction,
            'previous_hash': previous_hash,
            'timestamp': time.time(),
            'validator': self.id,
            'proof': self.calculate_proof()
        }
        block_data['hash'] = self.hash_block(block_data)
        return block_data

    @staticmethod
    def hash_block(block_data):
        block_string = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def calculate_proof():
        return random.randint(0, 100)
