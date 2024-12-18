import struct #used only to pack to bytes object and unpack to integer
import time

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

class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.tree = self.build_merkle_tree([self.transaction_to_string(transaction) for transaction in transactions])

    def transaction_to_string(self, transaction):
        return f"{transaction.sender}:{transaction.receiver}:{transaction.amount}"

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
    def __init__(self, previous_hash, transactions, difficulty=4):
        self.previous_hash = previous_hash
        self.timestamp = int(time.time())
        self.transactions = transactions
        self.merkle_root = MerkleTree(transactions).get_merkle_root()
        self.nonce = 0
        self.difficulty = difficulty
        self.hash = self.create_hash()

    def create_hash(self):
        block_data = f"{self.previous_hash}{self.timestamp}{self.merkle_root}{self.nonce}"
        return hash(block_data)

    def mine_block(self):
        correctNumOfZeros = '0' * self.difficulty
        while True:
            block_hash = self.create_hash()
            if block_hash[:self.difficulty] == correctNumOfZeros:
                return block_hash
            self.nonce += 1


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block("0", [Transaction("adilet", "adilet", 0)])
        self.chain.append(genesis_block)

    def add_block(self, transactions):
        last_block = self.chain[-1]
        new_block = Block(last_block.hash, transactions)
        self.chain.append(new_block)

    def validate_blockchain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.create_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

            if current_block.merkle_root != MerkleTree(current_block.transactions).get_merkle_root():
                return False

        return True

    def print_chain(self):
        for block in self.chain:
            print(f"Block Hash: {block.hash}")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Merkle Root: {block.merkle_root}")
            print(" ")

transactions = [
    Transaction("aaa", "aaa", 10),
    Transaction("bbb", "bbb", 20),
    Transaction("ccc", "ccc", 30),
    Transaction("ddd", "ddd", 40),
    Transaction("eee", "eee", 50),
    Transaction("fff", "fff", 60),
    Transaction("ggg", "ggg", 70),
    Transaction("hhh", "hhh", 80),
    Transaction("iii", "iii", 90),
    Transaction("jjj", "jjj", 100)
]

blockchain = Blockchain()
for transaction in transactions:
    blockchain.add_block(transactions)

blockchain.print_chain()

if blockchain.validate_blockchain():
    print("Blockchain is valid")