"""

"""
import crypto_utils as crypto

import hashlib
import json
import sqlite3
import datetime
import os

DB_PATH = 'db/blockchain.db'


def get_db_conn() -> sqlite3.Connection:
    """
    Helper function to establish db connection.
    """
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database file not found: {DB_PATH}. Please initialize the database and try again.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # enables column access by name
    return conn


def pull_latest():
    """
    Fetch all data from the latest block.

    Returns raw JSON data.
    """
    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        # Query: Get the block with the highest index
        cursor.execute('''
            SELECT * FROM Blockchain
            ORDER BY id DESC
            LIMIT 1
        ''')

        row = cursor.fetchone()
        conn.close()

        if row:
            # Convert the SQLite row object to a dictionary for JSON formatting
            block_data = dict(row)
            return block_data
        else:
            return None

    except sqlite3.Error:
        return None


def pull_all():
    """
    Fetch all data from all blocks present in the blockchain.

    Returns raw JSON data.
    """
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM Blockchain
            ORDER BY id ASC
        ''')
        rows = cursor.fetchall()
        conn.close()

        if rows:
            # Conver the SQLite row objects to dictionaries for JSON formatting
            block_data = [dict(row) for row in rows]
            return block_data
        else:
            return None

    except sqlite3.Error:
        return None


def construct_current_hash(id, timestamp, previous_hash, payload_hash):
    """Construct the SHA256 hash for a blockchain block header.

    Combines block metadata into a deterministic string representation and
    computes the SHA256 digest to create the block's unique fingerprint.

    Args:
        id (int): The block's position in the chain.
        timestamp (str): Timestamp of block creation (ISO 8601 format recommended).
        previous_hash (str): SHA256 hash of the previous block's header.
        payload_hash (str): SHA256 hash of the block's payload data.

    Returns:
        str: 64-character hexadecimal SHA256 digest representing the block header.

    Note:
        The header data is serialized with sorted keys to ensure deterministic
        output regardless of dictionary ordering.
    """
    # Construct the header data structure
    header_data = {
        "id": id,
        "timestamp": timestamp,
        "previous_hash": previous_hash,
        "payload_hash": payload_hash
    }

    # Convert header data to a consistent string so it can be hashed
    hash_object = hashlib.sha256(json.dumps(header_data, sort_keys=True).encode('utf-8'))
    current_hash = hash_object.hexdigest()

    return current_hash


def construct_payload_hash(payload: list) -> str:
    # generate SHA-256 hash from payload
    raw_hash = hashlib.sha256(json.dumps(payload).encode('utf-8'))
    payload_hash = raw_hash.hexdigest()
    return payload_hash


def add_block(payload: list[str]):
    previous_block = pull_latest()
    if previous_block is None:
        print("Please initialize the blockchain with a genesis block and try again.")
        return

    id = previous_block['id'] + 1
    timestamp = str(datetime.datetime.now())
    previous_hash = previous_block['current_hash']
    payload_hash = construct_payload_hash(payload)
    current_hash = construct_current_hash(id, timestamp, previous_hash, payload_hash)
    payload_json = json.dumps(payload)
    signature = crypto.sign_block(current_hash)

    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO Blockchain (id, timestamp, previous_hash, payload_hash, current_hash, payload, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (id, timestamp, previous_hash, payload_hash, current_hash, payload_json, signature))
        conn.commit()
        print("New block appended.\n")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        conn.close()



def generate_genesis_block(cursor: sqlite3.Cursor):
    """
    Generate the genesis block for the blockchain database.

    """
    id = 0
    # 🚩 Does this have security implications?
    timestamp = str(datetime.datetime.now())
    previous_hash = '0' * 64   # previous hash of genesis block is all 0's

    payload      = []
    payload_hash = construct_payload_hash(payload)
    current_hash = construct_current_hash(id, timestamp, previous_hash, payload_hash)
    signature    = crypto.sign_block(current_hash)

    # Convert payload list to a json string for db storage
    payload_json = json.dumps(payload)

    # Add the genesis block onto the database.
    cursor.execute('''
        INSERT INTO Blockchain (id, timestamp, previous_hash, payload_hash, current_hash, payload, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (id, timestamp, previous_hash, payload_hash, current_hash, payload_json, signature))



def init_blockchain_db():
    """Initializes an SQLite database in DB_PATH,
    instantiates a Blockchain table,
    and creates and appends a genesis block as its first row.

    🚧 TODO 🚧
    - error checking
    """
    try:
        # Creates the database file if it doesn't exist yet
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("DROP TABLE IF EXISTS Blockchain")

        # Initialize the Blockchain table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Blockchain (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                previous_hash TEXT,
                payload_hash TEXT,
                current_hash TEXT,
                payload TEXT,
                signature TEXT
            )
            ''')
        print("Blockchain database initialized.\n")
        print("Generating genesis block...")
        generate_genesis_block(cursor)
        conn.commit()
        print("Genesis block created and appended.\n")

    except sqlite3.Error as e:
        print("Error initializing the blockchain:", e)
        return
    finally:
        conn.close()
