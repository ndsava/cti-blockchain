"""
Client-side code.

Includes instructions for end nodes to connect to the blockchain.

1. Authorized nodes generate an SSH key pair🔑
    - in real life maybe after agreeing with the CA the new client
        could email the username and public SSH key to the CA
    - the key delivery is omitted in this project due to time constraints

2. After receiving the SSH key, an end node only needs to input
   `ssh -i ~/.ssh/cti-blockchain <USERNAME>@<SERVER_IP> -N -L 5000:127.0.0.1:5000`
   to access the blockchain.
   It says: "Whenever I access port 5000 on my computer,
   forward that traffic securely to port 5000 on the CA's computer."

3. Once the SSH tunnel is established, users can request the CA's public key 🔑
    through the '/get_public_key' endpoint.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import requests
import base64
import json
import os

SERVER_ADDRESS = 'http://127.0.0.1:5000'
PUBLIC_KEY_FILE = 'ca_public_key.pem'


def get_public_key():
    print("* Fetching CA's public key...")
    # 🚩 nested try clause?
    try:
        # Request and save to file the CA's public key
        request = requests.get(f"{SERVER_ADDRESS}/get_public_key")
        print("* Saving key to current working directory as ca_public_key.pem...")
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(request.content)
        print("✅ Public key saved successfully.\n")

    except requests.RequestException as e:
        print(f"Error with fetching key: {e}")


def load_public_key():
    try:
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    except Exception as e:
        print(f"Failed to load public key: {e}")
        return

    # Make sure loaded key is RSA
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Loaded key is not an RSA private key.")

    return public_key


def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, block_hash: bytes) -> int:
    """
    Checks whether a given block signature is authentic
    (signed with the CA's private key) by verifying it
    against the corresponding public key.

    Returns 1 if the signature is valid,
    otherwise raises an Exception and returns 0
    if signature is invalid, or -1 if signature
    cannot be verified.
    """
    try:
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


def pull_latest():
    try:
        response = requests.get(f"{SERVER_ADDRESS}/pull_latest")
        # 🚩 Prevents the program silently continuing with error responses
        response.raise_for_status()

        data = response.json()

        # Check API's response status before continuing
        if data.get("status") != "success":
            return None

        # Return the block data as a dictionary
        return data.get("block", {})

    except requests.RequestException as e:
        print(f"Error with reading the blockchain: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error with decoding block JSON: {e}")
        return None


def pull_all():
    try:
        response = requests.get(f"{SERVER_ADDRESS}/pull_all")
        # 🚩 Prevents the program silently continuing with error responses
        response.raise_for_status()

        data = response.json()

        # Check API's response status before continuing
        if data.get("status") != "success":
            return None

        # Return the blocks as a list of block dictionaries
        return data.get("blocks", [])

    except requests.RequestException as e:
        print(f"Error reading the blockchain: {e}\n")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding block JSON: {e}\n")
        return None


def validate_latest():
    """
    Validates the newest block in the blockchain by
    checking the validity of the block's signature
    against the CA's public key. Does not check
    hash validity with the predecessing block.
    """
    # Load the public key from file
    public_key = load_public_key()
    if not public_key:
        print("Cannot load public key. Aborting...\n")
        return

    # Pull the latest block from the server
    block = pull_latest()
    if not block:
        print("Cannot fetch the latest block. Aborting...\n")
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
        print(f"\nERROR: Verification of block #{id}'s signature failed for an unknown reason.")
        print("Aborting...\n\n")
        return
    else:
        print(f"✅ Signature of block #{id} is valid. ✅\n\n")


def validate_all():
    """
    Validates the entire blockchain by checking the validity
    of each block's signature against the CA's public key as well as
    each current hash by comparing it to the previous block's hash.
    """
    # Load the public key from file
    public_key = load_public_key()
    if not public_key:
        print("Cannot load public key. Aborting...\n")
        return

    # Load all blocks into memory
    blocks = pull_all()
    if not blocks:
        print("Blockchain is empty (no blocks found). Aborting...\n")
        return

    previous_hash_predecessor = bytes.fromhex('0' * 64) # Bytes representation

    # Validate each block starting from the genesis block
    for block in blocks:
        block_copy = block.copy() # Copy block to avoid modifying the original data
        id = block_copy.get('id')
        previous_hash_hex = block_copy.get('previous_hash')
        previous_hash = bytes.fromhex(previous_hash_hex) # Decode to bytes

        # Check hash validity
        if previous_hash != previous_hash_predecessor:
            print(f"❌ WARNING: Broken hash link detected in block #{id} ❌\n\n")
            print("Aborting validation process...\n\n")
            return

        signature_b64 = block_copy.get('signature')
        hash_hex = block_copy.get('current_hash')
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
            print(f"\nERROR: Verification of block #{id}'s signature failed for an unknown reason.")
            print("Aborting validation process...\n\n")
            return
        else:
            print(f"✅ Signature of block #{id} is valid. ✅")

        previous_hash_predecessor = current_hash

    print("\n✅ The hash chain appears intact. ✅\n\n")


def print_latest():
    """
    """
    # Pretty print the block if fetched successfully
    block = pull_latest()
    if not block:
        print("Error: Failed to receive block data from server.")
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
    """
    # Pretty print the block if fetched successfully
    blocks = pull_all()
    if not blocks:
        print("Blockchain is empty (no blocks found).")
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


def event_loop():
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
                print('''Provide one of the following commands (without '') to choose what to do.
                'help'         to show all commands.
                'key'          to request and save the CA's public key locally.
                'pull new'     to read the latest block.
                'pull all'     to read all blocks.
                'validate new' to validate the signature of the latest block.
                'validate all' to validate the integrity of the blockchain.
                'exit'         to quit the program.

                ''')
            case 'key':
                get_public_key()
            case 'pull new':
                print_latest()
            case 'pull all':
                print_all()
            case 'validate new':
                if not os.path.exists(PUBLIC_KEY_FILE):
                    print(f"Error! '{PUBLIC_KEY_FILE}' not found in current working directory.")
                    print("Run the command 'key' to fetch the CA's public key first and try again.\n")
                    continue
                validate_latest()
            case 'validate all':
                if not os.path.exists(PUBLIC_KEY_FILE):
                    print(f"Error! '{PUBLIC_KEY_FILE}' not found in current working directory.")
                    print("Run the command 'key' to fetch the CA's public key and try again.\n")
                    continue
                validate_all()
            case 'exit':
                print("Bye!")
                return
            case _:
                print("Unknown command.\n")
                continue


def main():
    # Print welcome screen
    print("+--------------------------------+")
    print("| WELCOME TO THE CTI-BLOCKCHAIN! |")
    print("+--------------------------------+\n")

    # ON CLIENT MACHINE:
    print("Please generate an SSH key with")
    print("`cd ~/.ssh`")
    print("`ssh-keygen -t rsa -b 4096 -f cti-blockchain`")
    print("if you haven't already.\n")

    print("Push public SSH key onto server with secure copy")
    print("`cd ~/.ssh`")
    print("`scp cti-blockchain.pub <SERVER>@<SERVER_IP>:/home/<SERVER>/.ssh/authorized_keys`\n")

    print("After transmitting cti-blockchain.pub to the server,")
    print("you may establish the SSH tunnel with")
    print("`ssh -i ~/.ssh/cti-blockchain <USERNAME>@<SERVER_IP> -N -L 5000:127.0.0.1:5000`\n\n")

    event_loop()

if __name__ == "__main__":
    main()
