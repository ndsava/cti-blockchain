"""
Blockchain CA's CLI tool for managing blockchain operations.
The CA should run this alongside app.py, in the same network.

Operations include
    * Generating an RSA key pair
    * (Re)Initializing the blockchain database
    * Adding new blocks
    * Reading existing blocks
    * Validating the blockchain

"""
import blockchain
import crypto_utils as crypto

from crypto_utils import PRIVATE_KEY_PATH
from crypto_utils import PUBLIC_KEY_PATH
from blockchain import DB_PATH

import os
import json
from pathlib import Path

ROOT = Path(__file__).parent
KEYS_DIR = f"{ROOT}/keys"
DB_DIR = f"{ROOT}/db"


def sanitize_payload(payload: str) -> list[str]:
    if payload.strip() == "":
        print("No payload provided. Aborting...\n")
        return []

    split_payload = payload.split()
    # Ensure that each item in the list is a valid IPv4 address
    for ip in split_payload:
        if not is_valid_ipv4(ip):
            print(f"Invalid IPv4 address: {ip}. Aborting...\n")
            return []
    return split_payload


def is_valid_ipv4(ip: str) -> bool:
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or int(part) < 0 or int(part) > 255:
                return False
        return True
    except:
        return False


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
                'help'     to show all commands.
                'init'     to (re)initialize the blockchain.
                'pull new' to read the latest block.
                'pull all' to read all blocks.
                'add'      to add a new block.
                'validate' to validate integrity of the blockchain.
                'keys'     to (re)generate cryptographic keys.
                'exit'     to quit the program.

                ''')


            case 'init':
                print(f"WARNING: Initializing the blockchain overrides any existing databases in `./{DB_PATH}`.")
                print(f"Make sure cryptographic keys `./{PRIVATE_KEY_PATH}` and `./{PUBLIC_KEY_PATH}` exist.")
                confirmation = input("Are you sure you want to continue? [y/n]: ")
                if confirmation == 'y' or confirmation == "yes":
                    print()
                    if not crypto.keys_exist():
                        print("Cannot find public nor/or private key. Please make sure they exist.\n")
                        continue
                    print("Initializing the blockchain database...")
                    blockchain.init_blockchain_db()
                else:
                    print("Aborting...\n")


            case 'add':
                if not crypto.keys_exist():
                    print("Cannot find public nor/or private key. Please make sure they exist.\n")
                    continue
                if not os.path.exists(DB_PATH):
                    print(f"Database file not found in `{DB_PATH}`. Please initialize the database and try again.\n")
                    continue

                payload = input("Please provide a list of IPv4 addresses separated by whitespaces: ")
                sanitized_payload = sanitize_payload(payload)
                if not sanitized_payload:
                    continue
                blockchain.add_block(sanitized_payload)


            case 'pull new':
                block = blockchain.pull_latest()
                if block is None:
                    continue

                print("Here's the latest block:\n")
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


            case 'pull all':
                blocks = blockchain.pull_all()
                if blocks is None:
                    continue

                print("Here is the entire blockchain:\n")
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


            case 'validate':
                # 🚧 TODO 🚧
                continue


            case 'keys':
                print("WARNING: Generating the RSA key pair will overwrite any existing keys in `./keys/`.")
                print("Overwriting existing keys will render any blockchain database that uses them broken.")
                confirmation = input("Are you sure you want to regenarate the RSA key pair? [y/n]: ")
                if confirmation == 'y' or confirmation == 'yes':
                    print("Deleting any existing keys...")
                    print("Generating a new key pair...\n")
                    crypto.generate_keys()
                else:
                    print("Aborting...\n")


            case 'exit':
                print("Bye!")
                return

            case _:
                print("Unknown command.\n")


def main():
    # Print welcome screen
    print("+--------------------------------+")
    print("| WELCOME TO THE CTI-BLOCKCHAIN! |")
    print("+--------------------------------+\n")

    # Create necessary empty directories
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(DB_DIR, exist_ok=True)

    # Warn about missing RSA keys
    if not crypto.keys_exist():
        print(f"Cannot find {PUBLIC_KEY_PATH} nor/or {PRIVATE_KEY_PATH}.")
        print("Please make sure they exist before commencing database operations.\n")

    event_loop()


if __name__=="__main__":
    main()
