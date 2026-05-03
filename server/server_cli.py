"""
 CTI Blockchain CA CLI Tool

This module implements the Command-Line Interface (CLI) for the Central Authority (CA)
to manage the private blockchain system. It provides direct, local access to all
blockchain operations without exposing them over the network.

System design:
    * Runs locally on the CA's machine alongside the Flask API server (app.py).
    * Provides direct database access via the 'blockchain' module, bypassing the API.
    * All cryptographic operations (key generation, signing) are performed locally.
    * 🚩 No transmission of private keys or secrets over the network.
    * 🚩 Separated from Flask API to minimize attack surface (write operations isolated).

Security notes:
    🚩 Network Isolation: This tool runs locally only; no network endpoints are exposed.
       All blockchain write operations are restricted to this CLI to prevent remote
       modification of the blockchain.

    🚩 Key Management: RSA private keys are generated, encrypted, and stored locally
       in 'keys/'. They are NEVER transmitted over the network, even over the SSH tunnel.
       The SSH tunnel is used only for serving the public key via API access (Flask app).

    🚩 Destructive Operations: Commands like 'keys' and 'init' can irreversibly destroy
       existing data (keys or database). Confirmation is required before execution.

    🚩 Input Validation: IPv4 payloads are validated before block creation to prevent
       malformed data from entering the blockchain.

Operations include
    * Generating an RSA key pair
    * (Re)Initializing the blockchain database
    * Adding new blocks
    * Reading existing blocks
    * Validating the blockchain 🚧 TODO

"""
import blockchain
import crypto_utils as crypto

from crypto_utils import PRIVATE_KEY_PATH
from crypto_utils import PUBLIC_KEY_PATH
from blockchain import DB_PATH

import os
from pathlib import Path

ROOT = Path(__file__).parent
KEYS_DIR = f"{ROOT}/keys"
DB_DIR = f"{ROOT}/db"
# ☢️ Define repeated printout as a constant
ABORT_MSG = "Aborting...\n"


def sanitize_payload(payload: str) -> list[str]:
    """
     Validate and sanitize a space-separated string of IPv4 addresses.

    Splits the input payload into individual IP addresses and validates
    each one to ensure it conforms to IPv4 format requirements.

    Args:
        payload (str): Space-separated string of IPv4 addresses to validate.

    Returns:
        list[str]: List of validated IPv4 addresses, or empty list if validation fails.

    Note:
        Returns an empty list if the payload is empty or contains any invalid IPs.
        Invalid entries trigger an error message and abort processing.
    """
    if payload.strip() == "":
        print("No payload provided.")
        print(ABORT_MSG)
        return []

    split_payload = payload.split()
    # Ensure that each item in the list is a valid IPv4 address
    for ip in split_payload:
        if not is_valid_ipv4(ip):
            print(f"Invalid IPv4 address: {ip}.")
            print(ABORT_MSG)
            return []
    return split_payload


def is_valid_ipv4(ip: str) -> bool:
    """
     Check whether a string conforms to IPv4 address format.

    Checks that the input has exactly four octets separated by periods,
    where each octet is a digit between 0 and 255 inclusive.

    Args:
        ip (str): String to validate as an IPv4 address.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.

    Note:
        Does not check for reserved or private IP ranges.
        Uses exception handling to catch malformed numeric conversions.
    """
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        for octet in octets:
            if not octet.isdigit() or int(octet) < 0 or int(octet) > 255:
                return False
        return True
    # 🚩 Using except Exception instead of a bare except clause
    # as per PEP 760 to avoid overly broad exception handling
    except Exception:
        return False


def _check_prerequisites(keys_check=True, db_check=True) -> bool:
    """
     Verify that required resources (RSA keys, database) exist before operations.

    Checks for the existence of cryptographic key files and/or the blockchain
    database file, depending on the flags provided. Prints user-friendly error
    messages if prerequisites are missing.

    Args:
        keys_check (bool): Whether to verify RSA key existence (default: True).
        db_check (bool): Whether to verify database file existence (default: True).

    Returns:
        bool: True if all requested prerequisites exist, False otherwise.

    Note:
        Prints specific error messages for each missing prerequisite.
        Returns False immediately upon first failure (short-circuit evaluation).
        Used by CLI command handlers to prevent operations on invalid state.
        Private function (prefixed with _) as it's only used internally.
    """
    if keys_check:
        # Check if RSA key pair exists
        if not crypto.keys_exist():
            print("Cannot find public nor/or private key.")
            print("Please generate them with 'keys' and try again.\n")
            return False
    if db_check:
        # Check if db file exists
        if not os.path.exists(DB_PATH):
            print(f"Database file not found in `{DB_PATH}`.")
            print("Please initialize the database with 'init' and try again.\n")
            return False
    return True


def print_help_screen():
    """
     Display the list of available CLI commands and their descriptions.

    Prints a formatted help menu to the console detailing all valid commands
    for the CA operator, including 'keys', 'init', 'add', 'pull', 'validate',
    and 'exit'.

    Args:
        None

    Returns:
        None

    Note:
        The output is static and does not reflect dynamic system state.
    """
    print('''Provide one of the following commands to choose what to do.
        'help'     to show all commands.
        'keys'     to (re)generate cryptographic keys.
        'init'     to (re)initialize the blockchain.
        'pull new' to read the latest block.
        'pull all' to read all blocks.
        'add'      to add a new block.
        'validate' to validate integrity of the blockchain.
        'exit'     to quit the program.

    ''')


def generate_rsa_key_pair():
    """
     Handle the generation and regeneration of the CA's RSA key pair.

    Prompts the user for confirmation before overwriting existing keys,
    deletes old keys if confirmed, and generates a new 4096-bit RSA pair.
    This is a destructive operation that invalidates any blockchain data
    signed by the previous keys.

    Args:
        None

    Returns:
        None

    Note:
        ⚠️ Destructive: Overwriting keys breaks the trust chain for all
           previously signed blocks. The blockchain will need re-initialization.
        Creates the 'keys/' directory if it does not exist.
        Aborts silently if the user declines the confirmation prompt.
    """
    print("❗️ WARNING: Generating the RSA key pair will overwrite any existing keys in `keys/`.")
    print("Overwriting existing keys will render any blockchain database that uses them broken.\n")
    confirmation = input("Are you sure you want to regenarate the RSA key pair? [y/n]: ")
    print()
    if confirmation == 'y' or confirmation == 'yes':
        # Create /keys if it doesn't exist
        os.makedirs(KEYS_DIR, exist_ok=True)
        print("Deleting any existing keys...")
        # Overwrite any existing keys
        # ❗️ WARNING: irreversible operation - potential for data loss
        crypto.delete_keys()
        print("Generating a new key pair...\n")
        crypto.generate_keys()
    else:
        print(ABORT_MSG)


def initialize_blockchain():
    """
     Handle the initialization or re-initialization of the blockchain database.

    Prompts the user for confirmation, verifies the existence of cryptographic
    keys, creates the database directory if needed, and calls the core
    initialization function to create the genesis block.

    Args:
        None

    Returns:
        None

    Note:
        ⚠️ Destructive: Re-initializing drops the existing 'Blockchain' table,
           permanently deleting all historical blocks.
        Prerequisite: RSA keys must exist; otherwise, the operation aborts.
        Aborts silently if the user declines the confirmation prompt.
    """
    print(f"❗️ WARNING: Initializing the blockchain overrides any existing databases in `{DB_PATH}`.\n")
    print(f"Make sure cryptographic keys `{PRIVATE_KEY_PATH}` and `{PUBLIC_KEY_PATH}` exist.\n")
    confirmation = input("Are you sure you want to continue? [y/n]: ")
    if confirmation == 'y' or confirmation == "yes":
        print()
        # Make sure the RSA key pair exists
        if not _check_prerequisites(True, False):
            return
        print("* Initializing the blockchain database...")
        # Create /db if it doesn't exist
        os.makedirs(DB_DIR, exist_ok=True)
        blockchain.init_blockchain_db()
    else:
        print(ABORT_MSG)


def add_new_block():
    """
     Handle the creation and signing of a new blockchain block.

    Validates prerequisites (keys and database existence), prompts the user
    for a payload of IPv4 addresses, sanitizes the input, and adds the
    validated payload as a new block to the chain.

    Args:
        None

    Returns:
        None

    Note:
        Prerequisites:
            - RSA keys must exist.
            - Database must be initialized.
        Input Validation:
            - Payload is validated via `sanitize_payload()`.
            - Empty or invalid payloads abort the operation.
        The new block is signed by the CA's private key before insertion.
    """
    # Make sure the keys and db file exist
    if not _check_prerequisites():
        return

    payload = input("Please provide a list of IPv4 addresses separated by whitespaces: ")
    sanitized_payload = sanitize_payload(payload)
    if not sanitized_payload:
        print("Please make sure you provide one or more IPv4 addresses in the correct format, e.g.")
        print("9.9.9.9 127.0.0.1\n")
        return
    blockchain.add_block(sanitized_payload)


def cmd_loop():
    """
     Run the interactive CLI command loop for blockchain management.

    Presents a menu-driven interface allowing the CA operator to perform
    blockchain operations including initialization, block addition, retrieval,
    validation (🚧), and key management. Delegates operations to private helper
    functions for better code organization.

    Args:
        None

    Returns:
        None

    Note:
        Runs indefinitely until the user selects 'exit'.
        Commands are matched via Python 3.10+ structural pattern matching.
        Prompts for confirmation on destructive operations (init, keys).
        Validates prerequisites before read/write operations.
        ☢️ Separate helper functions encapsulate command logic.
    """
    while True:
        # Print info screen
        print("🟪 --- CTI-BLOCKCHAIN --- 🟪")
        print("What would you like to do?")
        print("'help' to show more details.\n")

        option = input("Command: ")
        print("--------------------")
        print()
        match option:
            case 'help':
                print_help_screen()
            case 'keys':
                generate_rsa_key_pair()
            case 'init':
                initialize_blockchain()
            case 'add':
                add_new_block()

            case 'pull new':
                # Make sure the database exists
                if not _check_prerequisites(False, True):
                    continue
                blockchain.print_latest()

            case 'pull all':
                # Make sure the database exists
                if not _check_prerequisites(False, True):
                    continue
                blockchain.print_all()

            case 'validate':
                # 🚧 TODO 🚧
                continue

            case 'exit':
                print("Bye!")
                return
            case _:
                print("Unknown command.\n")
                print("Make sure you enter commands without apostrophes")
                print("(e.g. help instead of 'help').\n")


def main():
    """
     Initialize and launch the CTI Blockchain CLI application.

    Sets up required directory structures, checks for cryptographic key
    existence, and starts the interactive command loop.

    Args:
        None

    Returns:
        None

    Note:
        Creates 'keys/' and 'db/' directories if they don't exist.
        Warns user if RSA keys are missing before operations begin.
        Entry point when script is executed directly.
    """
    # Print welcome screen
    print("+--------------------------------+")
    print("| WELCOME TO THE CTI-BLOCKCHAIN! |")
    print("+--------------------------------+\n")

    # Create necessary empty directories
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(DB_DIR, exist_ok=True)

    # Warn about missing RSA keys
    if not crypto.keys_exist():
        print(f"Cannot find `{PUBLIC_KEY_PATH}` nor/or `{PRIVATE_KEY_PATH}`.")
        print("Please make you generate an RSA key pair with `keys` before commencing database operations.\n")

    cmd_loop()


if __name__=="__main__":
    main()
