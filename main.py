import struct
import time
import random
from typing import Tuple, Dict
import json

def hash(text):
    consts = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    hashValues = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]


    def right_rotate(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


    def padding(message):
        original_length = len(message) * 8
        message += b"\x80"
        while (len(message) * 8) % 512 != 448:
            message += b"\x00"
        message += struct.pack("!Q", original_length)
        return message


    def process_chunk(chunk, hashValues):
        w = [0] * 64
        for i in range(16):
            w[i] = struct.unpack("!I", chunk[i * 4:(i + 1) * 4])[0]
        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = hashValues

        for i in range(64):
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + consts[i] + w[i]) & 0xFFFFFFFF
            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        hashValues[0] = (hashValues[0] + a) & 0xFFFFFFFF
        hashValues[1] = (hashValues[1] + b) & 0xFFFFFFFF
        hashValues[2] = (hashValues[2] + c) & 0xFFFFFFFF
        hashValues[3] = (hashValues[3] + d) & 0xFFFFFFFF
        hashValues[4] = (hashValues[4] + e) & 0xFFFFFFFF
        hashValues[5] = (hashValues[5] + f) & 0xFFFFFFFF
        hashValues[6] = (hashValues[6] + g) & 0xFFFFFFFF
        hashValues[7] = (hashValues[7] + h) & 0xFFFFFFFF

    message = text.encode('utf-8')
    message = padding(message)

    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]
        process_chunk(chunk, hashValues)

    hash_result = ''
    for value in hashValues:
        hash_result += format(value, '08x')
    return hash_result

#///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#

def is_prime(n: int, k: int = 5) -> bool:
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int = 1024) -> int:
    while True:
        n = random.getrandbits(bits)
        if n % 2 == 0:
            n += 1
        if is_prime(n):
            return n


def generate_keypair(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537

    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, d, _ = extended_gcd(e, phi)
    d = d % phi
    if d < 0:
        d += phi

    return (e, n), (d, n)


class Wallet:
    def __init__(self, name: str):
        self.name = name
        self.public_key, self.private_key = generate_keypair()
        self.address = str(self.public_key[0]) + str(self.public_key[1])[-8:]

    def sign_transaction(self, transaction_data: str) -> int:
        message = int.from_bytes(transaction_data.encode(), 'big')
        signature = pow(message, self.private_key[0], self.private_key[1])
        return signature


class Transaction:
    def __init__(self, sender: Wallet, receiver: str, amount: float):
        self.sender_address = sender.address
        self.receiver_address = receiver
        self.amount = amount
        self.sender_public_key = sender.public_key
        self.transaction_data = f"{self.sender_address}:{self.receiver_address}:{self.amount}"
        self.signature = sender.sign_transaction(self.transaction_data)

    def verify_signature(self) -> bool:
        message = int.from_bytes(self.transaction_data.encode(), 'big')
        decrypted_signature = pow(self.signature, self.sender_public_key[0], self.sender_public_key[1])
        return message == decrypted_signature

    def to_dict(self):
        return {
            'sender_address': self.sender_address,
            'receiver_address': self.receiver_address,
            'amount': self.amount,
            'sender_public_key': (self.sender_public_key[0], self.sender_public_key[1]),
            'transaction_data': self.transaction_data,
            'signature': self.signature
        }

    @classmethod
    def from_dict(cls, data: dict):
        transaction = cls.__new__(cls)
        transaction.sender_address = data['sender_address']
        transaction.receiver_address = data['receiver_address']
        transaction.amount = data['amount']
        transaction.sender_public_key = tuple(data['sender_public_key'])
        transaction.transaction_data = data['transaction_data']
        transaction.signature = data['signature']
        return transaction


class TransactionDatabase:
    def __init__(self, filename="transactions.txt"):
        self.filename = filename

    def save_transaction(self, transaction: Transaction):
        try:
            transaction_dict = transaction.to_dict()

            transactions = self.load_all_transactions_dict()
            transactions.append(transaction_dict)

            with open(self.filename, 'w') as f:
                json.dump(transactions, f, indent=2)

            print(f"Transaction saved to {self.filename}")

        except Exception as e:
            print(f"Error saving transaction: {str(e)}")

    def load_all_transactions_dict(self):
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f"Error loading transactions: {str(e)}")
            return []

    def load_all_transactions(self):
        transaction_dicts = self.load_all_transactions_dict()
        return [Transaction.from_dict(tx_dict) for tx_dict in transaction_dicts]

    def clear_database(self):
        try:
            with open(self.filename, 'w') as f:
                json.dump([], f)
            print(f"Database {self.filename} cleared")
        except Exception as e:
            print(f"Error clearing database: {str(e)}")


class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.tree = self.build_merkle_tree([self.transaction_to_string(transaction) for transaction in transactions])

    def transaction_to_string(self, transaction: Transaction) -> str:
        return transaction.transaction_data

    def build_merkle_tree(self, transaction_hashes):
        if len(transaction_hashes) == 1:
            return transaction_hashes[0]

        while len(transaction_hashes) > 1:
            if len(transaction_hashes) % 2 != 0:
                transaction_hashes.append(transaction_hashes[-1])

            transaction_hashes = [hash(transaction_hashes[i] + transaction_hashes[i + 1])
                                  for i in range(0, len(transaction_hashes), 2)]

        return transaction_hashes[0]

    def get_merkle_root(self):
        return self.tree


class Block:
    def __init__(self, previous_hash: str, transactions: list, difficulty: int = 4):
        self.previous_hash = previous_hash
        self.timestamp = int(time.time())
        self.transactions = transactions
        self.merkle_root = MerkleTree(transactions).get_merkle_root()
        self.nonce = 0
        self.difficulty = difficulty
        self.hash = None
        self.mine_block()

    def create_hash(self) -> str:
        block_data = f"{self.previous_hash}{self.timestamp}{self.merkle_root}{self.nonce}"
        return hash(block_data)

    def mine_block(self) -> str:
        target = '0' * self.difficulty
        while True:
            current_hash = self.create_hash()
            if current_hash.startswith(target):
                self.hash = current_hash
                return current_hash
            self.nonce += 1


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.wallets: Dict[str, Wallet] = {}
        self.transaction_db = TransactionDatabase()
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_wallet = Wallet("genesis")
        self.wallets["genesis"] = genesis_wallet
        genesis_transaction = Transaction(genesis_wallet, genesis_wallet.address, 0)
        genesis_block = Block("0", [genesis_transaction])
        self.chain.append(genesis_block)

    def add_wallet(self, wallet: Wallet):
        self.wallets[wallet.address] = wallet

    def add_transaction(self, transaction: Transaction) -> bool:
        if not transaction.verify_signature():
            raise ValueError("Transaction signature is invalid")

        self.transaction_db.save_transaction(transaction)
        self.pending_transactions.append(transaction)
        return True

    def load_pending_transactions(self):
        transactions = self.transaction_db.load_all_transactions()
        print(f"Loaded {len(transactions)} transactions from database")
        return transactions

    def mine_pending_transactions(self):
        if not self.pending_transactions:
            self.pending_transactions = self.load_pending_transactions()

        if self.pending_transactions:
            new_block = Block(self.chain[-1].hash, self.pending_transactions)
            self.chain.append(new_block)
            self.pending_transactions = []
            self.transaction_db.clear_database()

    def validate_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            print(f"\nValidating block {i}...")

            calculated_hash = current_block.create_hash()
            if current_block.hash != calculated_hash:
                print(f"Block {i} hash is invalid!")
                return False
            print(f"Block {i} hash is valid")

            if current_block.previous_hash != previous_block.hash:
                print(f"Block {i} previous hash reference is invalid!")
                return False
            print(f"Block {i} previous hash reference is valid")

            calculated_merkle_root = MerkleTree(current_block.transactions).get_merkle_root()
            if current_block.merkle_root != calculated_merkle_root:
                print(f"Block {i} Merkle root is invalid!")
                return False
            print(f"Block {i} Merkle root is valid")

            for tx_index, transaction in enumerate(current_block.transactions):
                if not transaction.verify_signature():
                    print(f"Transaction {tx_index} in block {i} has invalid signature!")
                    return False
                print(f"Transaction {tx_index} in block {i} is valid")
                return True


if __name__ == "__main__":
    def print_file_contents(filename):
        print(f"\nContents of {filename}:")
        try:
            with open(filename, 'r') as f:
                print(f.read())
        except FileNotFoundError:
            print(f"File {filename} does not exist")


    print("Creating blockchain...")
    blockchain = Blockchain()

    print("\nCreating wallets...")
    rustem = Wallet("rustem")
    adilet = Wallet("adilet")
    marlan = Wallet("marlan")

    print("\nRegistering wallets with blockchain...")
    blockchain.add_wallet(rustem)
    blockchain.add_wallet(adilet)
    blockchain.add_wallet(marlan)

    try:
        print("\nCreating and saving first batch of transactions...")

        tx1 = Transaction(rustem, adilet.address, 50)
        print(f"Created transaction: Rustem -> Adilet, Amount: 50")
        blockchain.add_transaction(tx1)

        tx2 = Transaction(adilet, marlan.address, 30)
        print(f"Created transaction: Adilet -> Marlan, Amount: 30")
        blockchain.add_transaction(tx2)

        tx3 = Transaction(marlan, rustem.address, 10)
        print(f"Created transaction: Marlan -> Rustem, Amount: 10")
        blockchain.add_transaction(tx3)

        print("\nMining block with current transactions...")
        blockchain.mine_pending_transactions()

        print("\nCreating second batch of transactions...")

        tx4 = Transaction(rustem, marlan.address, 25)
        print(f"Created transaction: Rustem -> Marlan, Amount: 25")
        blockchain.add_transaction(tx4)

        tx5 = Transaction(adilet, rustem.address, 15)
        print(f"Created transaction: Adilet -> Rustem, Amount: 15")
        blockchain.add_transaction(tx5)

        print("\nMining block with second batch of transactions...")
        blockchain.mine_pending_transactions()

        print("\nValidating blockchain...")
        if blockchain.validate_chain():
            print("\nBlockchain is valid!")

            print("\nFinal blockchain state:")
            for i, block in enumerate(blockchain.chain):
                print(f"\nBlock {i}:")
                print(f"Hash: {block.hash}")
                print(f"Previous hash: {block.previous_hash}")
                print(f"Merkle root: {block.merkle_root}")
                print(f"Number of transactions: {len(block.transactions)}")

                print("\nTransactions in block:")
                for idx, tx in enumerate(block.transactions):
                    print(f"\nTransaction {idx + 1}:")
                    print(f"From: {tx.sender_address}")
                    print(f"To: {tx.receiver_address}")
                    print(f"Amount: {tx.amount}")
    except ValueError as e:
        print(f"\nError: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        raise e

    with open("transactions.txt", "w") as f:
        f.write("[]")