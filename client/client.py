"""
 CTI Blockchain client module

This module implements the client-side logic for interacting with the private
blockchain network. It handles secure communication via an SSH tunnel,
retrieval of the CA's public key, and validation of blockchain integrity.
Includes instructions for end nodes on how to connect to the blockchain.

1. Authorized nodes generate an SSH key pair🔑
    - in real life maybe after agreeing with the CA a new client
        could email (preferably some more secure way)
        the public SSH key to the CA
    - the key delivery is omitted in this project due to time constraints,
        but is flagged as a critical security consideration

2. After delivering the SSH key, an end node only needs to input
   `ssh -i ~/.ssh/cti-blockchain <USERNAME>@<SERVER_IP> -N -L 5000:127.0.0.1:5000`
   to access the blockchain.
   It says: "Whenever I access port 5000 on my computer,
   forward that traffic securely to port 5000 on the CA's computer."

3. Once the SSH tunnel is established, users can request the CA's public key 🔑
    through the '/get_public_key' endpoint.


Authorized clients can:
    - 🚩 Establish secure connections via SSH port forwarding (localhost:5000)
    - Fetch and cache the CA's public key for signature verification
    - Retrieve block data (latest or full chain) from the server
    - 🚩 Validate block signatures (RSA-PSS) and hash chain integrity

Security architecture:
    - 🚩 Authorization: Only clients whose public SSH key the CA (server) possesses
      can establish a connection through the SSH tunnel.
    - 🚩 Transport Security: All HTTP traffic is tunneled through an SSH connection
      (port 5000 -> localhost:5000), ensuring confidentiality and integrity.
    - Authentication: Clients verify block signatures using the CA's RSA public key.
    - Key Management: The CA's public key is fetched once and stored locally
      (ca_public_key.pem) for subsequent verification.

Security notes:
    - 🚩 KEY DELIVERY: The initial transfer of the client's SSH public key to the CA
      is manual (email/SCP). In production, this should be automated via a secure
      registration portal or something similar.
    - 🚩 NO MUTUAL TLS: The server does not authenticate the client beyond the SSH
      tunnel. Any user with SSH access can query the blockchain.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from pathlib import Path
import requests
import base64
import json
import os

SERVER_ADDRESS = 'http://127.0.0.1:5000'
ROOT = Path(__file__).parent
PUBLIC_KEY_FILE = f"{ROOT}/ca_public_key.pem"


def get_public_key() -> bool:
    """
     Fetch and save the CA's public key from the server.

    Sends an HTTP GET request to the '/get_public_key' endpoint over the
    established SSH tunnel. If successful, saves the PEM-formatted key
    to 'ca_public_key.pem' in the source code directory.

    Args:
        None

    Returns:
        bool: True if the key was successfully fetched and saved,
              False if a network error, HTTP error, or timeout occurred.

    Note:
        Uses a 5-second timeout to prevent hanging if the server is unresponsive.
        Calls response.raise_for_status() to treat HTTP 4xx/5xx errors as exceptions.
        Overwrites any existing 'ca_public_key.pem' file.
    """
    print("* Fetching CA's public key...")
    try:
        # Request CA's public key and save it to file
        response = requests.get(f"{SERVER_ADDRESS}/get_public_key", timeout=5)
        # 🚩 Prevents the program silently continuing with error responses
        response.raise_for_status()
        print(f"* Saving key to `{ROOT}` as ca_public_key.pem...\n")
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(response.content)
        print("✅ Public key saved successfully.\n")
        return True

    except requests.HTTPError as e:
        print(f"Server error {e.response.status_code}: {e.response.text}\n")
        return False
    except requests.RequestException as e:
        print(f"Error with fetching key: {e}\n")
        return False


def load_public_key() -> rsa.RSAPublicKey | None:
    """
     Load the CA's public key from the local cache file.

    Reads 'ca_public_key.pem' from the source code directory,
    deserializes it into a cryptography RSA public key object,
    and validates that it is indeed an RSA key.

    Args:
        None

    Returns:
        rsa.RSAPublicKey | None: The loaded RSA public key object,
                                 or None if the file is missing, corrupt,
                                 or not an RSA key.

    Note:
        Catches FileNotFoundError, ValueError (corrupt format), and generic
        exceptions, printing user-friendly error messages instead of crashing.
        Returns None on any failure to allow graceful degradation in callers.
    """
    try:
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("Error: Cannot find public key file.")
        print("Aborting...\n")
        return None
    except ValueError as e:
        print("Error loading public key: ", e)
        print("Aborting...\n")
        return None
    except Exception as e:
        print("Failed to load public key: ", e)
        print("Aborting...\n")
        return None

    # Make sure loaded key is RSA
    if not isinstance(public_key, rsa.RSAPublicKey):
        print("Loaded key is not an RSA public key.")
        print("Aborting...\n")
        return None

    return public_key


def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, block_hash: bytes) -> int:
    """
     Verify the digital signature of a block hash using the CA's public key.

    Uses the RSA-PSS padding scheme with SHA-256 to verify that the provided
    signature was generated by the CA's private key for the given block hash.

    Args:
        public_key (rsa.RSAPublicKey): The CA's public key for verification.
        signature (bytes): The Base64-decoded digital signature.
        block_hash (bytes): The SHA-256 hash of the block header.

    Returns:
        int: 1 if the signature is valid,
             0 if the signature is invalid (forgery detected),
             -1 if an unexpected error occurred during verification.

    Note:
        🚩 Uses PSS padding with MGF1(SHA256) and MAX salt length for maximum security.
        The input hash is treated as a pre-hashed value (utils.Prehashed).
        Does not raise exceptions; returns status codes for easy integration.
    """
    try:
        # 🚩 Using library function with secure defaults
        public_key.verify(
            signature,
            block_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return 1
    except InvalidSignature:
        return 0
    except Exception as e:
        print(f"Verification error: {e}\n")
        return -1


def pull_latest() -> dict | None:
    """
     Retrieve the most recent block from the blockchain server.

    Sends an HTTP GET request to '/pull_latest' and returns the block data
    as a dictionary if the server responds with a 'success' status.

    Args:
        None

    Returns:
        dict | None: Dictionary containing the latest block's data,
                     or None if the request fails, times out, or the
                     server returns an error status.

    Note:
        Uses a 5-second timeout.
        Validates the JSON response structure and 'status' field.
        Catches network errors and JSON decode errors gracefully.
    """
    try:
        response = requests.get(f"{SERVER_ADDRESS}/pull_latest", timeout=5)
        # 🚩 Prevents the program silently continuing with error responses
        response.raise_for_status()

        data = response.json()

        # Check API's response status before continuing
        if data.get("status") != "success":
            return None

        # Return the block data as a dictionary
        return data.get("block", {})

    except requests.HTTPError as e:
        print(f"Server error {e.response.status_code}: {e.response.text}\n")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding block JSON: {e}\n")
        return None
    except requests.RequestException as e:
        print(f"Error reading the blockchain: {e}\n")
        return None


def pull_all() -> list[dict] | None:
    """
     Retrieve the entire blockchain from the server.

    Sends an HTTP GET request to '/pull_all' and returns a list of all
    block dictionaries if the server responds with a 'success' status.

    Args:
        None

    Returns:
        list[dict] | None: List of block dictionaries in chronological order,
                           or None if the request fails, times out, or the
                           server returns an error status.

    Note:
        Uses a 5-second timeout.
        Validates the JSON response structure and 'status' field.
        Catches network errors and JSON decode errors gracefully.
    """
    try:
        response = requests.get(f"{SERVER_ADDRESS}/pull_all", timeout=5)
        # 🚩 Prevents the program silently continuing with error responses
        response.raise_for_status()

        data = response.json()

        # Check API's response status before continuing
        if data.get("status") != "success":
            return None

        # Return the blocks as a list of block dictionaries
        return data.get("blocks", [])

    except requests.HTTPError as e:
        print(f"Server error {e.response.status_code}: {e.response.text}\n")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding block JSON: {e}\n")
        return None
    except requests.RequestException as e:
        print(f"Error reading the blockchain: {e}\n")
        return None


def validate_latest():
    """
     Validate the digital signature of the latest block only.

    Fetches the latest block and the CA's public key, then verifies the
    block's signature. Does NOT check the hash chain integrity (previous_hash).

    Args:
        None

    Returns:
        None

    Note:
        Prints detailed status messages (valid, invalid, or error).
        Aborts early if the public key cannot be loaded or the block is missing.
        Useful for quick checks without validating the entire chain history.
    """
    # Load the public key from file
    public_key = load_public_key()
    if not public_key:
        return

    # Pull the latest block from the server
    block = pull_latest()
    if not block:
        return

    # Extract block id, signature and hash
    id = block.get('id')
    signature_b64 = block.get('signature')
    hash_hex = block.get('current_hash')

    if not signature_b64 or not hash_hex:
        print("Error: Invalid block data (missing signature or hash).")
        return

    # Decode signature (from base64) and hash (from hexadecimal) to bytes
    signature_bytes = base64.b64decode(signature_b64)
    hash_bytes = bytes.fromhex(hash_hex)

    result = verify_signature(public_key, signature_bytes, hash_bytes)
    if result == 0: # Invalid signature
        print(f"\n❌ WARNING: Signature of block #{id} is invalid. ❌\n\n")
        return
    elif result == -1:  # Error
        print("Aborting...\n\n")
        return
    else:
        print(f"✅ Signature of block #{id} is valid. ✅\n\n")


def validate_all():
    """
     Validate the entire blockchain's integrity and signatures.

    Fetches all blocks and the CA's public key,
    then performs two checks for each block:
        1. Hash Chain Integrity: Verifies that each block's 'previous_hash'
           matches the 'current_hash' of its predecessor.
        2. Signature Validity: Verifies that each block is signed by the CA.

    Args:
        None

    Returns:
        None

    Note:
        Stops immediately upon detecting the first invalid hash link or signature.
        Prints detailed error messages indicating which block failed and why.
        The genesis block (id=0) is assumed to have a previous_hash of 64 zeros.
    """
    # Load the public key from file
    public_key = load_public_key()
    if not public_key:
        return

    # Load all blocks into memory
    blocks = pull_all()
    if not blocks:
        return

    previous_hash_predecessor = bytes.fromhex('0' * 64) # Bytes representation

    # Validate each block starting from the genesis block
    for block in blocks:
        block_copy = block.copy() # Copy block to avoid modifying the original data
        id = block_copy.get('id')
        previous_hash_hex = block_copy.get('previous_hash')
        signature_b64 = block_copy.get('signature')
        hash_hex = block_copy.get('current_hash')

        # Sanity check that all keys exist
        if not previous_hash_hex or not signature_b64 or not hash_hex:
            print(f"❌ Error: Missing key in block #{id} ❌\n\n")
            print("Aborting validation process...\n\n")
            return

        previous_hash = bytes.fromhex(previous_hash_hex) # Decode to bytes

        # Check hash validity
        if previous_hash != previous_hash_predecessor:
            print(f"❌ WARNING: Broken hash link detected in block #{id} ❌\n\n")
            print("Aborting validation process...\n\n")
            return

        # Decode signature (from base64) and hash (from hexadecimal) to bytes
        signature = base64.b64decode(signature_b64)
        current_hash = bytes.fromhex(hash_hex)

        # Verify signature validity
        result = verify_signature(public_key, signature, current_hash)

        # Stop the process if an invalid signature is found
        if result == 0:
            print(f"\n❌ WARNING: Signature of block #{id} is invalid. ❌")
            print("Aborting validation process...\n\n")
            return
        # Stop the process if signature cannot be verified
        elif result == -1:
            print(f"\nError occurred at block index #{id}.")
            print("Aborting validation process...\n\n")
            return
        else:
            print(f"✅ Signature of block #{id} is valid. ✅")

        previous_hash_predecessor = current_hash

    print("\n✅ The hash chain appears intact. ✅\n\n")


def print_latest():
    """
     Fetch and display the latest block in formatted JSON.

    Retrieves the latest block from the server, parses the 'payload' field
    from a JSON string to a Python list for readability, and prints the
    entire block structure with indentation.

    Args:
        None

    Returns:
        None

    Note:
        Gracefully handles non-JSON payload strings by skipping parsing.
        Prints an error message if the fetch fails.
    """
    # Pull latest block through the API
    block = pull_latest()
    if not block:
        return

    print("⛓️  Here's the latest block ⛓️\n")
    display_block = block.copy()

    # parse `payload` column as JSON
    if isinstance(display_block.get('payload'), str):
        try:
            display_block['payload'] = json.loads(display_block['payload'])
        except json.JSONDecodeError:
            pass  # Skip non-JSON strings

    print(json.dumps(display_block, indent=4))
    print()


def print_all():
    """
     Fetch and display all blocks in the blockchain in formatted JSON.

    Retrieves all blocks from the server, iterates through them, parses
    each 'payload' field from JSON string to list, and prints each block
    with indentation.

    Args:
        None

    Returns:
        None

    Note:
        Gracefully handles non-JSON payload strings by skipping parsing.
        Prints an error message if the blockchain is empty or fetch fails.
    """
    # Pull all blocks through the API
    blocks = pull_all()
    if not blocks:
        return

    print("⛓️  Here are all the blocks currently present in the blockchain ⛓️\n")
    for block in blocks:
        display_block = block.copy() # Copy block to avoid modifying the original data
        # parse `payload` column as JSON
        if isinstance(display_block.get('payload'), str):
            try:
                payload_list = json.loads(display_block['payload'])
                display_block['payload'] = payload_list
            except json.JSONDecodeError:
                pass  # Skip non-JSON strings

        print(json.dumps(display_block, indent=4))
        print()


def cmd_loop():
    """
     Run the interactive CLI command loop for the blockchain client.

    Presents a menu-driven interface allowing the user to fetch keys,
    view blocks, validate the chain, or exit. Commands are matched via
    Python 3.10+ structural pattern matching.

    Args:
        None

    Returns:
        None

    Note:
        Runs indefinitely until the user selects 'exit'.
        Checks for the existence of the public key file before validation commands.
        Provides helpful error messages if prerequisites (like the SSH tunnel)
        are missing.
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
                print('''Provide one of the following commands to choose what to do.
                'help'         to show all commands.
                'key'          to request the CA's public key and save it locally.
                'pull new'     to read the latest block.
                'pull all'     to read all blocks.
                'validate new' to validate the signature of the latest block.
                'validate all' to validate the integrity of the blockchain.
                'exit'         to quit the program.

                ''')
            case 'key':
                if not get_public_key():
                    print("Please check your connection and try again.\n")
            case 'pull new':
                print_latest()
            case 'pull all':
                print_all()
            case 'validate new':
                if not os.path.exists(PUBLIC_KEY_FILE):
                    print(f"ERROR: Public key file `{PUBLIC_KEY_FILE}` not found.")
                    print("Run the command 'key' to fetch the CA's public key first and try again.\n")
                    continue
                validate_latest()
            case 'validate all':
                if not os.path.exists(PUBLIC_KEY_FILE):
                    print(f"ERROR: Public key file `{PUBLIC_KEY_FILE}` not found.")
                    print("Run the command 'key' to fetch the CA's public key and try again.\n")
                    continue
                validate_all()
            case 'exit':
                print("Bye!")
                return
            case _:
                print("Unknown command.\n")
                print("Make sure you enter commands without apostrophes")
                print("(e.g. help instead of 'help').\n")


def main():
    """
     Initialize and launch the CTI Blockchain client application.

    Displays welcome instructions for setting up the SSH tunnel and
    generating SSH keys, then starts the interactive command loop.

    Args:
        None

    Returns:
        None

    Note:
        Prints manual instructions for SSH key generation and tunnel setup.
        Assumes the user has already established the SSH tunnel before running.
        Entry point when script is executed directly.
    """
    # Print welcome screen
    print("+--------------------------------+")
    print("| WELCOME TO THE CTI-BLOCKCHAIN! |")
    print("+--------------------------------+\n")

    # Client setup instructions
    print("Please generate an SSH key with")
    print("`cd ~/.ssh`")
    print("`ssh-keygen -t rsa -b 4096 -f cti-blockchain`")
    print("if you haven't already.\n")

    print("Push public SSH key onto server with secure copy")
    print("`cd ~/.ssh`")
    print("`scp cti-blockchain.pub <SERVER>@<SERVER_IP>:/home/<SERVER>/.ssh/authorized_keys`\n")

    print("After transmitting cti-blockchain.pub to the server,")
    print("you may establish the SSH tunnel through port 5000 with")
    print("`ssh -i ~/.ssh/cti-blockchain <USERNAME>@<SERVER_IP> -N -L 5000:127.0.0.1:5000`\n\n")

    cmd_loop()

if __name__ == "__main__":
    main()
