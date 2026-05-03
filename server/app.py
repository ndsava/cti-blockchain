"""
 CTI Blockchain server API module

This module implements the Flask-based REST API for the private blockchain system,
exposing read-only endpoints to authorized clients via SSH tunneling.

System design:
    * 🚩 Flask server binds explicitly to 127.0.0.1:5000 to prevent external access.
    * Clients authenticate via SSH keys stored in ~/.ssh/authorized_keys.
    * Business logic is delegated to the 'blockchain' module; this file handles
      only HTTP/JSON serialization and security filtering.
    * All server functions are separated from the Flask app to allow local execution
      via 'server_cli.py' on the CA's machine. This design enables:
        * Direct database access without exposing risky APIs.
        * No transmission of private keys or other secrets over the network.

Security Architecture & Constraints:
    - 🚩 Error Handling: Raw SQLite and server exceptions are logged internally
       but replaced with generic "Internal server error." messages to prevent
       leaking architectural details (e.g., table names, file paths) to clients.

    - 🚩 Transport Security: ALL endpoints are served exclusively over the SSH tunnel,
       providing transport-layer encryption. However, they do not perform additional
       client authentication beyond the SSH key access granted by the OS.

    - 🚩 API Scope: All these endpoints offer read-only operations; no data is modified
       through the API. Write operations are restricted to the local CLI tool
       (server_cli.py) to minimize the attack surface.

    - 🚩 File serving uses send_from_directory() to prevent directory traversal attacks.

Endpoints:
    * GET /              : Health check (confirms SSH tunnel is active)
    * GET /get_public_key: Returns CA's RSA public key (PEM format)
    * GET /pull_all      : Returns entire blockchain (list of blocks)
    * GET /pull_latest   : Returns the most recent block only
"""
import blockchain

from flask import Flask, jsonify, send_from_directory
import sqlite3

app = Flask(__name__)

HOST_IP = '127.0.0.1'
HOST_PORT = 5000
# ☢️ Define repeated error message as a constant
INTERNAL_SERVER_ERROR_MSG = "Internal server error."


@app.route("/")
def index():
    """
     Health check endpoint for verifying SSH tunnel connectivity.

    Returns a simple welcome message to confirm the Flask server is running
    and the SSH tunnel is properly established.

    Args:
        None

    Returns:
        str: Welcome message string.

    Note:
        Can be tested with `curl http://localhost:5000` from the client machine.
        Useful for diagnosing SSH tunnel or network connectivity issues.
    """
    return "Welcome to the CTI Blockchain!\n"


@app.route('/get_public_key')
def get_public_key():
    """
     Serve the CA's RSA public key to authorized clients.

    Returns the PEM-formatted public key file located in the 'keys/' directory.
    This key is used by clients to verify digital signatures on blockchain blocks.

    Args:
        None

    Returns:
        Response: Flask response object containing the public key file (PEM),
                  or a 404 error if the file is not found.

    Note:
        Uses send_from_directory() instead of send_file() to prevent directory
          traversal attacks (e.g., requesting '../../../etc/passwd').
        The public key is cached locally by clients after first fetch.
    """
    # Serve CA's public key file to client
    try:
        # 🚩 Using send_from_directory instead of send_file
        # to prevent directory traversal attacks
        return send_from_directory('keys', 'public_key.pem')
    except FileNotFoundError:
        return "Error: public key file not found.", 404


@app.route('/pull_all')
def read_all():
    """
     Retrieve the entire blockchain from the database.

    Queries the blockchain module for all blocks and returns them as a JSON
    array. If the blockchain is empty, returns a 404 error with a descriptive
    message.

    Args:
        None

    Returns:
        Response: Flask response object containing:
            - 200 OK with {"status": "success", "blocks": [...]}
            - 404 Not Found with {"status": "error", "message": "..."}
            - 500 Internal Server Error with generic error message

    Note:
        Empty blockchain is treated as an error (404), not a success.
        All blocks are returned in chronological order (genesis first).
    """
    try:
        blocks = blockchain.pull_all()

        if blocks:
            return jsonify({
                "status": "success",
                "blocks": blocks
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Blockchain is empty (no blocks found)."
            }), 404

    except sqlite3.Error as e:
        print("❌ SQLite error ❌\n", e) # 🚩 Log raw exceptions only internally
        return jsonify({
            "status": "error",
            # 🚩 Only send generic error message to clients
            # to avoid leaking internal architectural details
            "message": INTERNAL_SERVER_ERROR_MSG
        }), 500
    except Exception as e:
        print("❌ Server error ❌\n", e)
        return jsonify({
            "status": "error",
            "message": INTERNAL_SERVER_ERROR_MSG
        }), 500


@app.route('/pull_latest')
def read_latest():
    """
     Retrieve the most recent block from the blockchain.

    Queries the blockchain module for the latest block and returns it as a
    JSON object. If the blockchain is empty, returns a 404 error.

    Args:
        None

    Returns:
        Response: Flask response object containing:
            - 200 OK with {"status": "success", "block": {...}}
            - 404 Not Found with {"status": "error", "message": "..."}
            - 500 Internal Server Error with generic error message

    Note:
        Empty blockchain is treated as an error (404), not a success.
    """
    try:
        block = blockchain.pull_latest()

        if block:
            return jsonify({
                "status": "success",
                "block": block
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Blockchain is empty (no blocks found)."
            }), 404

    except sqlite3.Error as e:
        print("❌ SQLite error ❌\n", e)
        return jsonify({
            "status": "error",
            "message": INTERNAL_SERVER_ERROR_MSG
        }), 500
    except Exception as e:
        print("❌ Server error ❌\n", e)
        return jsonify({
            "status": "error",
            "message": INTERNAL_SERVER_ERROR_MSG
        }), 500


if __name__ == "__main__":
    """
     Launch the Flask development server on localhost:5000.

    🚩 Configures the server to bind explicitly to 127.0.0.1 (not 0.0.0.0)
      for security, ensuring it's only accessible via the SSH tunnel.
    🚩 Debug mode is disabled to prevent information leakage.

    Security Configuration:
        - host='127.0.0.1': Prevents external network access
        - debug=False: Disables debugger and detailed error pages
        - Port 5000: Default Flask port (can be changed via HOST_PORT)

        This script should be run on the CA's machine only.
        🚩 Clients connect via SSH tunnel, not direct network access.
    """
    # defaults to localhost (127.0.0.1:5000) if given no args,
    # but being explicit adds security in-depth
    app.run(host=HOST_IP, port=HOST_PORT, debug=False)
