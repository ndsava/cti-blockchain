"""
 CTI Blockchain operations module

Operations include (non-exhaustive)
    * Initializing the blockchain by creating the database and genesis block
    * Adding new blocks to the db
    * Retrieving blocks
    * 🚧 Validating the integrity of the blockchain

Architectural notes
    * Blocks are stored in an SQLite database (table called Blockchain)
      with fields for id, (creation) timestamp,
      hashes for previous block, current block, and payload,
      JSON-serialized payload data, and CA's signature of the current hash
    * Each block contains the previous block's hash, forming an immutable chain
    * Genesis block uses a null previous hash ('0'*64) as an anchor
    * The CA's digital signatures are applied via the crypto_utils module for authenticity

Security notes
    * All hash computations use SHA-256 for collision resistance
    * Timestamps are stored as ISO-format strings for consistency
    * Payload data is JSON-serialized before hashing and storage
    * 🚧

"""
import crypto_utils as crypto

import sqlite3
import hashlib
import datetime
import json
import os
from pathlib import Path

ROOT = Path(__file__).parent
DB_PATH = f'{ROOT}/db/blockchain.db'


def get_db_conn() -> sqlite3.Connection:
    """
     Establish a connection to the blockchain SQLite database.

    Opens a connection to the blockchain database file and configures
    row factory for named column access. Raises an error if the database
    file does not exist.

    Args:
        None

    Returns:
        sqlite3.Connection: Active database connection with Row factory enabled.

    Raises:
        FileNotFoundError: If the database file at DB_PATH does not exist.

    Note:
        The caller is responsible for closing the connection when done.
        DB_PATH is relative to the module's location (ROOT/db/blockchain.db).
    """
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(
            f"Database file not found in {DB_PATH}.\nPlease initialize the database with 'init' and try again.")
    # Creates the database file if it doesn't exist yet
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    return conn


def pull_latest() -> dict | None:
    """
     Fetch the newest block from the blockchain.

    Queries the database for the block with the highest id value,
    returning all its data as a dictionary.

    Args:
        None

    Returns:
        dict | None: Dictionary containing the latest block's data,
                     empty dict {} if the blockchain is empty,
                     or None if an error occurs during retrieval.

    Note:
        Uses ORDER BY id DESC with LIMIT 1 for efficient retrieval.
        Returns {} for empty blockchain (no blocks exist).
        Returns None only on sqlite3.Error exceptions.
    """
    try:
        with get_db_conn() as conn:
            cursor = conn.cursor()

            # Query the block with the highest index
            cursor.execute('''
                SELECT * FROM Blockchain
                ORDER BY id DESC
                LIMIT 1
            ''')

            row = cursor.fetchone()

            if row:
                # Convert the SQLite row object
                # to a dictionary for JSON formatting
                block_data = dict(row)
                return block_data
            else:
                return {}

    except sqlite3.Error as e:
        print("Error retrieving newest block: ", e)
        return None


def pull_all() -> list[dict] | None:
    """
     Fetch all data from all blocks present in the blockchain.

    Retrieves all blocks in chronological order and returns them
    as a list of dictionaries. Each dictionary represents
    one complete block with all its fields.

    Args:
        None

    Returns:
        list[dict] | None: List of block dictionaries in chain order,
                           empty list [] if the blockchain is empty,
                           or None if an error occurs during retrieval.

    Note:
        Uses ORDER BY id ASC to maintain chronological sequence
        (starting from genesis block).
        Returns [] for empty blockchain (no blocks exist).
        Returns None only on sqlite3.Error exceptions.
    """
    try:
        with get_db_conn() as conn:
            cursor = conn.cursor()

            # Query all blocks from oldest to newest
            cursor.execute('''
                SELECT * FROM Blockchain
                ORDER BY id ASC
            ''')
            rows = cursor.fetchall()

            if rows:
                # Convert the SQLite row objects
                # to dictionaries for JSON formatting
                block_data = [dict(row) for row in rows]
                return block_data
            else:
                return []

    except sqlite3.Error as e:
        print("Error retrieving blocks: ", e)
        return None


def print_latest():
    """
     Display the most recent block in formatted JSON output.

    Retrieves the latest block and prints its contents with pretty-printed
    JSON formatting. Automatically parses the payload column from JSON string
    to Python list for readable output.

    Args:
        None

    Returns:
        None

    Note:
        Gracefully handles non-JSON payload strings by skipping parsing.
        Prints an error message if pull_latest() returns None or an empry dict {}.
    """
    block = pull_latest()
    if block is None:
        return
    if block == {}:
        print("\nError fetching the latest block: the blockchain may be empty.\n")
        return

    print("⛓️  Here's the latest block ⛓️\n")
    display_block = block.copy()

    # parse `payload` column as JSON
    if isinstance(display_block['payload'], str):
        try:
            payload_list = json.loads(display_block['payload'])
            display_block['payload'] = payload_list
        except json.JSONDecodeError:
            pass  # Skip non-JSON strings

    print(json.dumps(display_block, indent=4))
    print()


def print_all():
    """
     Display all blocks in the blockchain in formatted JSON output.

    Retrieves all blocks and prints each one with pretty-printed JSON
    formatting. Automatically parses payload columns from JSON strings
    to Python lists for readable output.

    Args:
        None

    Returns:
        None

    Note:
        Gracefully handles non-JSON payload strings by skipping parsing.
        Prints an error message if pull_all() returns None or an empty list [].
    """
    blocks = pull_all()
    if blocks is None:
        return
    if blocks == []:
        print("\nError fetching blocks: the blockchain may be empty.\n")
        return

    print("⛓️  Here are all the blocks currently present in the blockchain ⛓️\n")
    for block in blocks:
        display_block = block.copy()

        # Parse `payload` column as JSON
        if isinstance(display_block['payload'], str):
            try:
                payload_list = json.loads(display_block['payload'])
                display_block['payload'] = payload_list
            except json.JSONDecodeError:
                pass  # Skip non-JSON strings

        print(json.dumps(display_block, indent=4))
        print()


def construct_current_hash(id: int, timestamp: str,
                        previous_hash: str, payload_hash: str) -> str:
    """
     Construct the SHA256 hash for a blockchain block header.

    Combines block metadata into a deterministic string representation and
    computes the SHA256 digest to create the block's unique fingerprint.

    Args:
        id (int): The block's position in the chain.
        timestamp (str): Timestamp of block creation.
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

    # Serialize header data into a consistent string before hashing
    header_str = json.dumps(header_data, sort_keys=True).encode('utf-8')
    hash_object = hashlib.sha256(header_str)
    # Convert the hash to a hexadecimal string digest
    current_hash = hash_object.hexdigest()

    return current_hash


def construct_payload_hash(payload: list[str]) -> str:
    """
     Generate a SHA-256 hash of the block payload data.

    Serializes the payload list to JSON and computes its SHA-256 digest,
    creating a fixed-size fingerprint of the block's payload data.

    Args:
        payload (list[str]): List of strings to be hashed
                            (depicting IPv4 addresses).

    Returns:
        str: 64-character hexadecimal SHA-256 digest of the payload.

    Note:
        Uses json.dumps() with sort_keys=True for deterministic output.
        The resulting hash is used in the block header for chain integrity.
    """
    # Serialize payload data into a consistent string before hashing
    payload_str = json.dumps(payload, sort_keys=True).encode('utf-8')
    # generate SHA-256 hash from serialized payload
    hash_object = hashlib.sha256(payload_str)
    payload_hash = hash_object.hexdigest()
    return payload_hash


def add_block(payload: list[str]):
    """
     Append a new block to the blockchain with cryptographic signing.

    Creates a new block by computing all required hashes, generating a
    timestamp, and obtaining a digital signature for the block header.
    Inserts the complete block into the database.

    Args:
        payload (list[str]): List of data items to store in the block
                                (validated IPv4 addresses).

    Returns:
        None

    Note:
        Requires the blockchain to be initialized with a genesis block first.
        Uses the CA's private key (via crypto.sign_block) for signing.
        Rolls back on database errors to maintain consistency.
        Prints status messages for success or failure.
        Caller is responsible for validating payload before calling.
        Checks for empty dict {} from pull_latest() to detect uninitialized chain.
    """
    previous_block = pull_latest()
    if previous_block is None:
        return
    if previous_block == {}:
        print("\nPlease initialize the blockchain with a genesis block and try again.\n")
        return

    id = previous_block['id'] + 1
    # 🚩 datetime.datetime should not have security implications
    # since it's not used to create security-critical randomness
    timestamp = str(datetime.datetime.now())
    previous_hash = previous_block['current_hash']
    payload_hash = construct_payload_hash(payload)
    current_hash = construct_current_hash(id, timestamp, previous_hash, payload_hash)
    payload_json = json.dumps(payload)
    signature = crypto.sign_block(current_hash)
    if signature is None:
        return

    try:
        with get_db_conn() as conn:
            cursor = conn.cursor()

            # 🚩 Use of parameterized statement to mitigate SQL injection
            cursor.execute('''
                INSERT INTO Blockchain (id, timestamp, previous_hash, payload_hash, current_hash, payload, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (id, timestamp, previous_hash, payload_hash, current_hash, payload_json, signature))

            print("✅ New block appended.\n")
    except sqlite3.Error as e:
        print("Error adding new block: ", e)


def generate_genesis_block(cursor: sqlite3.Cursor):
    """
     Generate the genesis block for the blockchain database.

    Creates and inserts the first block of the chain with id=0, a null
    previous hash, and signs it using the CA's private key. This block
    serves as the immutable anchor for the entire blockchain.

    Args:
        cursor (sqlite3.Cursor): Active database cursor for executing INSERT.

    Returns:
        None

    Note:
        Previous hash is set to 64 zeros ('0'*64) as there is no predecessor.
        Payload is an empty list for the genesis block.
    """
    id = 0
    # 🚩 datetime.datetime should not have security implications
    # since it's not used to create security-critical randomness
    timestamp = str(datetime.datetime.now())
    previous_hash = '0' * 64   # previous hash of genesis block is all 0's

    payload      = []
    payload_hash = construct_payload_hash(payload)
    current_hash = construct_current_hash(id, timestamp, previous_hash, payload_hash)
    signature    = crypto.sign_block(current_hash)

    # Convert payload list to a json string for db storage
    payload_json = json.dumps(payload)

    # Add the genesis block onto the database.
    # 🚩 Use of parameterized statement to mitigate SQL injection
    cursor.execute('''
        INSERT INTO Blockchain (id, timestamp, previous_hash, payload_hash, current_hash, payload, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (id, timestamp, previous_hash, payload_hash, current_hash, payload_json, signature))


def init_blockchain_db():
    """
     Initialize the blockchain database with schema and genesis block.

    Creates the SQLite database file and Blockchain table, then generates
    and inserts the genesis block. Drops any existing table first to ensure
    a clean initialization.

    Args:
        None

    Returns:
        None

    Note:
        This operation destroys any existing blockchain data
           by dropping the table before recreation.
        Prints status messages for each initialization step.
    """
    try:
        with get_db_conn() as conn:
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
            print("✅ Genesis block created and appended.\n")

    # Raise these errors explicitly to avoid silent failing
    except sqlite3.Error as e:
        print("Error initializing the blockchain:", e)
        raise
    except Exception as e:
        print("Unexpected error:", e)
        raise
