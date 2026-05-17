"""
 CTI Blockchain cryptographic utilities module

This module provides the core cryptographic operations for the private blockchain system,
focusing on RSA key management, digital signatures, and secure passphrase handling.

Operations include:
    * Generation and storage of RSA 4096-bit key pairs (for CA)
    * Digital signature creation and verification using PSS padding
    * Secure encryption of the CA's private key at rest using PKCS#8 format
    * Passphrase validation and secure input handling

Cryptographic details:
    * Algorithm: RSA-4096 with public exponent of 65537
    * Hashing: SHA-256 for signatures and key derivation
    * Key Storage: Private key encrypted with
                    BestAvailableEncryption (password-protected),
                    Public key stored in plaintext (PEM)
    * Key Format: PKCS#8 (RFC 5958) for interoperability and standard compliance
    * Encoding: Base64 for database-friendly signature storage, PEM for RSA keys
    * cryptography module: All cryptographic functions are carried out through
                            the use of Python's `cryptography` module. It's
                            considered the recommended library for cryptographic
                            operations and primitives in Python, and is actively
                            maintained.

Security notes:
    * 🚩 NO KEY ROTATION: Keys are generated once and never rotated.
      Compromise of the private key invalidates the entire chain's trust.
    * 🚩 NO PASSPHRASE STORAGE: Passphrases are not stored long term.
      The CA entity must handle passphrase storage; it cannot be recovered if lost.
    * 🚩 MEMORY SAFETY: Passphrases are held in memory as bytes until garbage collection.
      No explicit zeroing (Python limitation).
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import UnsupportedAlgorithm
import getpass
import base64
import os
from pathlib import Path

ROOT = Path(__file__).parent
PRIVATE_KEY_PATH = f'{ROOT}/keys/private_key.pem'
PUBLIC_KEY_PATH = f'{ROOT}/keys/public_key.pem'
# ☢️ Define repeated printout as a constant
ABORT_MSG = "Aborting...\n"


def sign_block(current_hash: str) -> str | None:
    """
     Sign a block header hash using the CA's private RSA key.

    Loads the encrypted private key from disk, prompts for the passphrase,
    and generates a digital signature using the PSS padding scheme with
    SHA-256. The resulting signature is Base64-encoded for database storage.

    Args:
        current_hash (str): 64-character hexadecimal SHA-256 digest of the
                            block header to be signed.

    Returns:
        str | None: Base64-encoded string representing the digital signature,
                    or None if the key cannot be loaded or signing fails.

    Note:
        Delegates key loading to load_private_key(). If that function returns
        None, this function aborts gracefully without attempting to sign.

        The try/except block here primarily guards against errors during
        the actual signing operation (e.g., malformed current_hash input)
        or unexpected cryptographic failures.

        🚩 Uses PSS padding with MGF1(SHA256) and MAX salt length for
        maximum security against forgery attacks.

        The input hash is pre-hashed (utils.Prehashed) because the
        'current_hash' argument is already a SHA-256 digest.
    """
    try:
        # Load private key for signature
        private_key = load_private_key(PRIVATE_KEY_PATH)

        if private_key is None:
            print(ABORT_MSG)
            return None

        print("* Signing block...")
        # CA signs the current_hash with its private key
        # 🚩 Using library function with secure defaults
        signature = private_key.sign(
            bytes.fromhex(current_hash),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), # MGF1 as Mask
                                                   # Generation Function
                salt_length=padding.PSS.MAX_LENGTH), # Max salt length
            # current_hash is already hashed with SHA-256
            utils.Prehashed(hashes.SHA256())
        )
        # Encode raw bytes to Base64 for db storage
        signature = base64.b64encode(signature).decode('utf-8')
        return signature

    except ValueError as e:
        print("Error signing block: ", e)
        print(ABORT_MSG)
        return None
    except Exception as e:
        print("Unexpected error: ", e)
        print(ABORT_MSG)
        return None


def keys_exist() -> bool:
    """
     Check if both CA private and public key files exist on disk.

    Verifies the presence of the encrypted private key and the
    corresponding public key in the designated 'keys/' directory.

    Args:
        None

    Returns:
        bool: True if both key files exist, False otherwise.

    Note:
        Does not validate the integrity or validity of the keys,
        only their existence as files.
    """
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        return True
    return False


def delete_keys():
    """
     Remove the CA's private and public key files from disk.

    Deletes both the encrypted private key and the public key files.
    Uses 'missing_ok=True' to avoid errors if files are already absent.

    Args:
        None

    Returns:
        None

    Note:
        WARNING: This operation is irreversible.
            Ensure backups exist if keys are needed later.
        Does not securely wipe the disk sectors (standard unlink).
        For high-security environments, use 'shred' or similar tools.
    """
    private_key_path = Path(PRIVATE_KEY_PATH)
    public_key_path = Path(PUBLIC_KEY_PATH)
    private_key_path.unlink(missing_ok=True)
    public_key_path.unlink(missing_ok=True)


def is_strong_password(password: str) -> bool:
    """
     Validate a passphrase against minimum security requirements.

    Checks that the password meets the following criteria:
        - At least 8 characters in length
        - Contains at least one uppercase letter
        - Contains at least one lowercase letter
        - Contains at least one digit

    Args:
        password (str): The passphrase string to validate.

    Returns:
        bool: True if the password meets all requirements, False otherwise.

    Note:
        🚩 This is a basic heuristic. For production systems, consider:
        - Minimum length of 16 characters
        - Checking against known breach databases (HaveIBeenPwned)
        - Entropy calculations
        - Rejecting common dictionary words
    """
    if len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    return has_upper and has_lower and has_digit


def create_password() -> bytes | None:
    """
     Prompt the user to enter and validate a secure passphrase.

    Interactively requests a passphrase via the terminal (hidden input),
    validates it against strength requirements, and retries up to 3 times.
    Returns the encoded password bytes on success, or None on failure/abort.

    Args:
        None

    Returns:
        bytes | None: UTF-8 encoded passphrase if valid, None if aborted
                      or after 3 failed attempts.

    Note:
        🚩 MEMORY SAFETY: The returned password bytes reside in memory
            until the Python Garbage Collector (GC) reclaims them.
            Python does not guarantee immediate zeroing of memory upon
            deallocation, leaving a theoretical risk of memory scraping
            attacks.
        Uses 'getpass' to echo of typed characters.
        Handles EOFError (e.g., piped input) and GetPassWarning gracefully.
        Prints clear error messages and aborts flow on failure.
    """
    print("Enter a secure passphrase to encrypt your private key.")
    print("The passphrase must include at least")
    print("- 8 characters")
    print("- 1 upper case letter")
    print("- 1 digit\n")
    print("❗️ WARNING: You must remember this passphrase or store it securely.\n")
    try:
        counter = 3
        while counter > 0:
            password = getpass.getpass("Enter a secure passphrase: "
                        ).encode('utf-8')
            print()
            if is_strong_password(password.decode('utf-8')):
                return password
            print("❌ Given passphrase does not meet the security requirements.")
            counter -= 1

        print("\nNo valid passphrase provided.")
        print(ABORT_MSG)
        return None

    except EOFError as e:
        print("\nError: ", e)
        print(ABORT_MSG)
        return None
    except getpass.GetPassWarning as e:
        print("\nError: ", e)
        print(ABORT_MSG)
        return None


def load_private_key(private_key_path: str) -> rsa.RSAPrivateKey | None:
    """
     Load and decrypt the CA's private RSA key from disk.

    Reads the encrypted PEM file, prompts for the decryption passphrase,
    and returns the decrypted RSA private key object. Validates that the
    loaded key is indeed an RSA key.

    Args:
        private_key_path (str): Path to the encrypted private key file.

    Returns:
        rsa.RSAPrivateKey | None: The decrypted RSA private key object,
                                    or None if loading fails (wrong password,
                                    missing file, or corrupt format).

    Note:
        🚩 MEMORY SAFETY: The passphrase entered by the user is held in
            memory as bytes until the Garbage Collector (GC) reclaims it.
            Python lacks a built-in mechanism to securely zero out memory
            buffers, posing a theoretical risk of memory dumping attacks.

        Catches FileNotFoundError, ValueError (wrong password/format),
            TypeError, and UnsupportedAlgorithm, printing user-friendly
            messages and returning None instead of crashing.

        The passphrase is requested interactively via 'getpass'.
        The key is validated to ensure it matches the expected RSA type.
    """
    try:
        # Only 1 chance to input the correct private key passphrase
        # 🚩 A way of rate limiting, although it doesn't
        # *block* consecutive attempts
        password = getpass.getpass("Enter passphrase for your private key: "
                    ).encode('utf-8')
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=default_backend()
            )

        # Make sure loaded key is RSA
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError(f"Loaded key is not an RSA private key.\n{ABORT_MSG}")

        return private_key

    except FileNotFoundError:
        print("Error: Cannot find private key file.")
        print(ABORT_MSG)
        return None
    except ValueError as e:
        print("Error loading private key: ", e)
        return None
    except TypeError:
        print("Error: Invalid passphrase or key format.")
        return None
    except UnsupportedAlgorithm as e:
        print("Error: ", e)
        return None
    except Exception as e:
        print("Unexpected error loading key: ", e)
        return None


def generate_keys():
    """
     Generate the CA's public/private key pair using the cryptography library.

    Generates a 4096-bit RSA key pair, encrypts the private key with a
    user-provided passphrase using PKCS#8 format, and saves both keys to disk.

    Args:
        None

    Returns:
        None

    Note:
        🚩 SECURITY LIMITATION: These keys are never rotated.
            Loss or compromise of this key (incl. passphrase)
            invalidates the entire blockchain's trust model.

        - Key Size: 4096 bits (resistant to classical and near-term quantum attacks)
        - Format: PKCS#8 (RFC 5958) for the private key
        - Encryption: BestAvailableEncryption (may change over time)

        Requires a valid passphrase via create_password().
        Aborts if the user fails to provide a strong passphrase.
    """
    try:
        # Generate private RSA key
        # 🚩 Using library function with secure defaults
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Get password for encrypting the private key with
        password = create_password()
        if password is None:
            return

        # Serialize and store the encrypted private key to local file
        # 🚩 Using cryptography library function with BestAvailableEncryption
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8, # Standardized format (RFC 5958)
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(pem)
        print(f"\n🔑 Private key created in `{PRIVATE_KEY_PATH}`")

        # Generate public RSA key
        public_key = private_key.public_key()
        # Serialize and store public key to local file
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pem)
            print(f"\n🔑 Public key created in `{PUBLIC_KEY_PATH}`\n")

    except ValueError as e:
        print("Error generating keys: ", e)
        return
    except OSError as e:
        print("Error writing key files: ", e)
        return
    except Exception as e:
        print("Unexpected error: ", e)
        return
