'''

'''
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import getpass
import base64
#import secrets
import os
import sys
from pathlib import Path

PRIVATE_KEY_PATH = 'keys/private_key.pem'
PUBLIC_KEY_PATH = 'keys/public_key.pem'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def sign_block(current_hash):
    """🚧 Add error handling 🚧

    """
    print("Signing block...")
    # Load private key for signature
    private_key = load_private_key(PRIVATE_KEY_PATH)

    # CA signs the current_hash with its private key
    signature = private_key.sign(
        bytes.fromhex(current_hash),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        utils.Prehashed(hashes.SHA256())
    )
    # Encode raw bytes to Base64 for db storage
    signature = base64.b64encode(signature).decode('utf-8')
    return signature


def keys_exist():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        return True
    return False


def delete_keys():
    private_key_path = Path(PRIVATE_KEY_PATH)
    public_key_path = Path(PUBLIC_KEY_PATH)
    private_key_path.unlink(missing_ok=True)
    public_key_path.unlink(missing_ok=True)


def load_private_key(private_key_path: str) -> rsa.RSAPrivateKey:
    """🚧 Add error handling 🚧

    """
    password = getpass.getpass("Enter passphrase for your private key: ").encode('utf-8')
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password,
            backend=default_backend()
        )

    # Make sure loaded key is RSA
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Loaded key is not an RSA private key.")

    return private_key


def generate_keys():
    """Generate the CA's public/private key pair using the cryptography library.

    🚩 SECURITY LIMITATION: These keys are never rotated. Loss/compromise leads to catastrophic failure.
    """
    # Overwrite any existing keys
    # WARNING: potential for data loss
    delete_keys()

    # Generate private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Encrypt private key with password
    # 🚩 🚧 TODO: Implement enforcing strong password
    try:
        password = getpass.getpass("Enter a secure passphrase to encrypt your private key: ").encode('utf-8')
    except EOFError as e:
        print("Error: ", e)
        print("Aborting...")
        sys.exit(1)
    except getpass.GetPassWarning as e:
        print("Error: ", e)
        print("Aborting...")
        sys.exit(1)

    # Serialize and store the encrypted private key to local file
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(pem)
    print(f"Private key created in `{SCRIPT_DIR}/{PRIVATE_KEY_PATH}`...")

    # Generate public RSA key
    public_key = private_key.public_key()
    # Serialize and store public key to local file
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(pem)
    print(f"Public key created in `{SCRIPT_DIR}/{PUBLIC_KEY_PATH}`...\n")
