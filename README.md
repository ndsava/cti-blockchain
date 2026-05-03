time spent: 69 h (incl. zoom)

# CTI Dissemination Blockchain

This program simulates a simplified private blockchain owned by a CA (e.g. a CTI producer company). Only the CA can append new blocks (signature with private key). The blocks contain malicious IP addresses discovered by the CA. Authorized users can subscribe to the blockchain and pull new blocks as they are appended, as well as verify each block with the CA's public key.


## Implementation structure

Central Authority ("server") (Python / Flask)
- initializes the blockchain
- generates cryptographic keys
- stores the private key locally
- adds new blocks signed with the private key
- authenticates users to establish an SSH tunnel

Client program ("users" / "nodes") (Python, Flask)
- authenticated nodes must have the client-side code to
  - request CA's public key
  - read blocks
  - validate blocks

Database (SQLite):
- stores the blockchain in a table format

Networking (SSH, Flask):
- nodes authenticate through SSH tunneling
- Flask acts as an API server to enable the client-side functionality


## How to use the program
Follow these instructions in order to test/demo the project.
NOTE: This project has been developed and tested exclusively on Linux machines (Ubuntu and its derivatives). Other platforms are not supported (but may work).

**Set up the CA server**  
**SSH config**  
PublicKeyAuthentication must be turned on while PasswordAuthentication must be turned off. For added security it is advisable to turn PermitRootLogin off.
1. In `/etc/ssh/sshd_config`
  make sure you have
  - `PubkeyAuthentication yes`
  - `PasswordAuthentication no`
  - `PermitRootLogin no` (optional).
2. Restart SSH with  
  - `sudo systemctl restart ssh`.
3. Ensure ~/.ssh/authorized_keys exists on the server machine  
  - `mkdir ~/.ssh/authorized_keys`.
3. Ensure correct permissions with
  - `chmod 600 ~/.ssh/authorized_keys`.

**Add new client**
1. The client generates an SSH key pair:
  - `cd ~/.ssh`
  - `ssh-keygen -t rsa -b 4096 -f cti-blockchain`
2. The public SSH key must be manually copied to `~/.ssh/authorized_keys` on the server machine. You may use whatever method to accomplish this. Below is an overview of how I did it. Note that for this method both the remote client and server machines must have public IP addresses.  
  On my own machine (acting as an intermediary), I pulled the public key from the client to my CWD, then sent it to the server:
  - `scp <USER>@<CLIENT_IP>:/home/<USER>/.ssh/cti-blockchain.pub .`
  - `scp cti-blockchain.pub <SERVER>@<SERVER_IP>:/home/<SERVER>/.ssh/client_ssh`
  On the server machine:
  - `cd ~/.ssh`
  - `cat client_ssh >> authorized_keys`
  Make sure the client's key is appended to a new line in authorized_keys.

**Run the server program**  
Note: Your server machine must have a public IP address to establish the SSH tunnel from client machines.
1. Clone the server-side code from github.com/ndsava/cti-blockchain/server onto your machine.
2. Navigate to the project root.
3. Create a Python virtual environment with
  - `python3 -m venv .venv`
  and activate it with
  - `source .venv/bin/activate`.
4. Install the project requirements with
  - `pip install -r requirements.txt`.
5. Run the server CLI program with
  - `python3 server/server_cli.py`.  
  Now you can act as the CA, creating and managing the blockchain.

**Start the Flask API**  
1. On the server machine, navigate to the project root and activate your virtual environment
  - `source .venv/bin/activate`.
2. To expose the Flask endpoint to your clients, run
  - `python3 server/app.py`.

**Run the client program**  
Note: Follow all previous instructions before running the client program.  
On the client machine
1. Establish the SSH tunnel to the server with
  - `ssh -i ~/.ssh/cti-blockchain <USERNAME>@<SERVER_IP> -N -L 5000:127.0.0.1:5000`.
2. Open a new terminal window and navigate to the project root.  
  You can test the SSH tunnel connection with
  - `curl localhost:5000/` (make sure app.py is running on the server).
3. Create a Python virtual environment with
  - `python3 -m venv .venv`
  and activate it with
  - `source .venv/bin/activate`.
4. Install the project requirements with
  - `pip install -r requirements.txt`.
5. Run the client CLI program with
  - `python3 client/client.py`.


## Security decisions & considerations (WIP)
Exposing the blockchain to authorized entities only has been identified as the largest security concern in this project. Therefore thorough research and consideration has been conducted to make the networking features as secure as possible. The conclusion was to keep the implementation as simple as possible to minimize coding errors and thus reduce the attack vector.
Ultimately, key-authorized SSH tunnelling through Flask on localhost was chosen as the means to grant access for authorized users to read the blockchain. This is in line with the project's scope and purpose, since it allows for exposing the server endpoint to the internet without direct public access. For production-grade security this might not be the best solution. Cloudflare Tunnel was another option but I wanted to keep control to myself instead of trusting a third-party.

The clients must request the CA's public RSA key only once to store it locally. This design was chosen over requesting the key freshly upon every block validation attempt to mitigate MitM attacks as well as improve reliability/availability (clients can validate blocks even though the server is down temporarily).

### Python modules
**cryptography**
The Python ´cryptography´ standard library's Hazmat layer is used to obtain established cryptographic primitives, namely RSA.

**getpass**

**flask**?


### Cryptography
The CA generates and stores a private-public key pair using RSA. For each key, the public exponent is 65537 and key length is 4096 bits. These are considered secure values for RSA.
The CA encrypts and stores the private key to a local file with password protection. 
The CA stores the public key on disk with no password.
