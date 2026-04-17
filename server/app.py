"""
- We expose the blockchain to authorized users through SSH tunnelling (which handles encryption of traffic automatically)

- Each user will generate an SSH key (and request the CA's public key) when they have been cleared to join

- We use Flask to set the server (CA) to listen on localhost (port 5000 for example)

- We store users' public SSH keys on the server (~/.ssh/authorized_keys) for easy management (addition, revocation)

- The Flask API exposes exclusively read-only endpoints for the clients (increased security, decreased attack surface)
    * /pull_latest /pull_all (read blocks)
    * /get_public_key (request CA's public RSA key for signature validation)

- All server functions are separated from the Flask app because they can be run locally on the CA's machine (python3 server_cli.py)
    * direct database access, no need for risky APIs
    * no transmission of private keys or other secrets over the network
"""
import blockchain

from flask import Flask, jsonify, send_from_directory
import sqlite3

app = Flask(__name__)

HOST_IP = '127.0.0.1'
HOST_PORT = 5000


"""
Landing page for the client-side of the program. Can be used
to check SSH tunnel connection with `curl http://localhost:5000`.
"""
@app.route("/")
def index():
    return "Welcome to the CTI Blockchain!"


@app.route('/get_public_key')
def get_public_key():
    # Serve CA's public key file to client
    try:
        # 🚩 Using send_from_directory instead of send_file
        # to prevent directory traversal attacks
        return send_from_directory('keys', 'public_key.pem')
    except FileNotFoundError:
        return "Error: public key file not found.", 404


@app.route('/pull_all')
def read_all():
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
        return jsonify({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/pull_latest')
def read_latest():
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
        return jsonify({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


if __name__ == "__main__":
    # defaults to localhost (127.0.0.1:5000) if given no args,
    # but being explicit adds security in-depth
    app.run(host=HOST_IP, port=HOST_PORT, debug=False)
