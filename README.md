# CTI Dissemination Blockchain

This program simulates a simplified private blockchain owned and managed by a Central Authority (e.g. a company who produces Cyber Threat Information). The role of the blockchain is to securely and transparently disseminate CTI to authorized entities. Only the CA can append new blocks by signing them with a private key. The blocks contain “malicious” IP addresses discovered by the CA. Authorized users may query the blockchain, reading blocks and verifying their integrity and validity with the CA's public key.


## Implementation structure

**Server - Central Authority (CA)**
- owns and manages the private blockchain
- only entity that can append new blocks
- maintains the blockchain records in an SQLite database
- generates and stores an RSA key pair
	- signs blocks with the secret key
	- distributes public key to client nodes
- runs the Flask app API to expose client endpoints
- maintains a list of authorized SSH keys to manage clients’ API access

**Clients**
- obtain access to the blockchain by providing the CA with their public SSH key
- connect to the database API through an SSH tunnel and
	- request the CA’s public key for validation operations 
	- read blocks from the blockchain
	- validate authenticity and integrity of blocks using the CA’s public key

**Blockchain**
- blocks contain fields for
	- block header
		- id
		- timestamp
		- payload hash
		- previous block’s header hash
	- block header hash
	- payload (list of IPv4 addresses)
	- CA’s digital signature of block header hash
- the blockchain is initialized with the genesis block (id = 0)
- each block contains the hash of its predecessor, creating a verifiable chain link
- each block’s header hash is signed by the CA for proof of authenticity

**Flask**
- serves a REST API
- exposes endpoints for clients to
	- fetch CA’s public RSA key
	- read blocks
	- validate blocks
- listens on localhost port 5000 on the CA’s machine

**SSH**
- serves as a local port forwading tool
- creates a tunnel allowing clients to connect to the server’s localhost
- the SSH keys act as acccess management for the Flask API
- offers automatic transport layer encryption


## How to use the program
At least 2 networked machines are required (1 server, 1 client), preferably in separate networks. The server machine must have a public IP address. Please follow these instructions in order. 

  
NOTE: This project has been developed and tested exclusively on Linux machines (Ubuntu and its derivatives). Other platforms are not supported. Python version 3.10+ required.

### Set up the server (CA)
**SSH config**  
OpenSSH must be installed and configured on the server machine. For testing purposes, you may not want to harden the SSH daemon too much as not to lock yourself out of the server machine (if using a cloud VM etc.). However, the following configurations should still be set:

1. In `/etc/ssh/sshd_config` on the server machine, make sure you have
  - `PubkeyAuthentication yes`
  - `PasswordAuthentication no`
  - `PermitRootLogin no` (optional)
2. Restart SSH with  
  - `sudo systemctl restart ssh`
3. Create ~/.ssh/authorized_keys on the server machine **if it doesn't exist**
  - `touch ~/.ssh/authorized_keys`
4. Ensure correct permissions with
  - `chmod 600 ~/.ssh/authorized_keys`

### Add new client
1. The client generates an SSH key pair:
  - `cd ~/.ssh`
  - `ssh-keygen -t rsa -b 4096 -f cti-blockchain`
2. The public SSH key must be manually copied to `~/.ssh/authorized_keys` on the server machine. You may use whatever method to accomplish this. Below is an overview of how I did it. Note that for this method both the remote client and server machines must have public IP addresses.  
  On my own machine (acting as an intermediary), I pulled the public key from the client to my `cwd`, then sent it to the server:
  - `scp <CLIENT_USER>@<CLIENT_IP>:/home/<CLIENT_USER>/.ssh/cti-blockchain.pub .`
  - `scp cti-blockchain.pub <SERVER_USER>@<SERVER_IP>:/home/<SERVER_USER>/.ssh/client_ssh`  
  On the server machine:
  - `cd ~/.ssh`
  - `cat client_ssh >> authorized_keys`  
  Make sure the client's key is appended to a new line in authorized_keys.

### Run the server program  
Note: The server machine must have a public IP address to establish the SSH tunnel from client machines.
1. Navigate to `/server` from the project root.
2. Create a Python virtual environment with
  - `python3 -m venv .venv`  
  and activate it with
  - `source .venv/bin/activate`
3. Install the project requirements with
  - `pip install -r requirements.txt`
4. Run the server CLI program with
  - `python3 server_cli.py`  
Now you can act as the CA, creating and managing the blockchain.

### Start the Flask API
1. On the server machine, activate your virtual environment in `.../project_root/server` with
  - `source .venv/bin/activate`
2. To expose the Flask endpoint to your clients, run
  - `python3 server/app.py`

### Run the client program
Note: Follow all previous instructions before running the client program.
On the client machine
1. Establish the SSH tunnel to the server with
  - `ssh -i ~/.ssh/cti-blockchain <SERVER_USER>@<SERVER_IP> -N -L 5000:127.0.0.1:5000`
2. Open a new terminal window and navigate to `/client` from the project root.  
  You can test the SSH tunnel connection with
  - `curl localhost:5000/` (make sure app.py is running on the server)
3. Create a Python virtual environment with
  - `python3 -m venv .venv`  
  and activate it with
  - `source .venv/bin/activate`
4. Install the project requirements with
  - `pip install -r requirements.txt`
5. Run the client CLI program with
  - `python3 client.py`  
You should now be able to access the API endpoints from the CLI program.

## Use of AI
Proton Lumo v1.3 has been used extensively throughout this project.  
**Design phase**  
I validated my ideas with AI to make sure they were feasible in the project’s
scope and time frame.  
**Implementation**  
AI was used to provide examples and snippets for various parts of the code, as well as
provide rules and guidelines for good coding practices in Python. I used Lumo as a mentor
to e.g. offer clues as to what exceptions certain lines of code may raise etc. AI was also
used to analyze error messages while debugging. All module-level comments and function
docstrings are AI-generated, but they have been manually reviewed and edited.  
**Security testing**  
I used AI to troubleshoot problems with setting up security tools, such as modifying the
Snyk Security YAML configuration file in GitHub actions.
