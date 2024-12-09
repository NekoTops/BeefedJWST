# JWKS server that utilizes an sqlite database to store private keys for later retrevial.
# Functions produced or modified in part with ChatGPT have been labled below
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from argon2 import PasswordHasher
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time
from collections import deque
import hashlib
from Crypto.Random import get_random_bytes
class RateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()

    def is_allowed(self):
        current_time = time.time()
        
        # Remove timestamps that are outside the time window
        while self.requests and self.requests[0] < current_time - self.time_window:
            self.requests.popleft()
        
        # Check if the current request can be allowed
        if len(self.requests) < self.max_requests:
            self.requests.append(current_time)
            return True
        return False


# Load AES key

aes_key = os.environ.get('NOT_MY_KEY')
if aes_key is None:
    raise ValueError("Encryption key NOT_MY_KEY not found in environment variables.")

def get_aes_key(aes_key):
    # Hash the key to ensure it is 32 bytes long for AES-256
    return hashlib.sha256(aes_key.encode('utf-8')).digest()
# Initialize the password hasher
ph = PasswordHasher(time_cost=2, memory_cost=2**16, parallelism=2, hash_len=32, salt_len=16)

# Set host defaults
hostName = "localhost"
serverPort = 8080

# Database setup
db_name = "totally_not_my_privateKeys.db"

# start database
############### Begin Database  Function Code ###############
# Connect DB and make query cursor
def init_db():  # produced in part with ChatGPT
    conn = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        email TEXT UNIQUE,
                        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP      
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_ip TEXT NOT NULL,
                        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user_id INTEGER,  
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
    conn.commit()
    conn.close()
# Store a new key in the database
valid_aes_key = get_aes_key(aes_key)
def encrypt_private_key(private_key):
    
     # Generate a random IV (16 bytes)
    iv = get_random_bytes(16)
    cipher = AES.new(valid_aes_key, AES.MODE_CBC, iv)
    
    # Encrypt the private key with padding
    encrypted_key = cipher.encrypt(pad(private_key, AES.block_size))
    
    # Base64 encode the IV and the encrypted key
    iv_encoded = base64.b64encode(iv).decode('utf-8')
    encrypted_key_encoded = base64.b64encode(encrypted_key).decode('utf-8')
    
    # Concatenate IV and encrypted key
    combined_data = iv_encoded + encrypted_key_encoded
    return combined_data
def store_key(private_key, exp):
    encrypted_data = encrypt_private_key(private_key)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO keys (key, exp) VALUES (?, ?)''', (encrypted_data, exp))
    conn.commit()
    conn.close()
def decrypt_private_key(iv, encrypted_key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(encrypted_key)
    cipher = AES.new(valid_aes_key, AES.MODE_CBC, iv)
    decrypted_key = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return decrypted_key
# Retrieve all active keys
def get_all_keys(include_expired=False):  # produced in part with ChatGPT
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    if include_expired:
        cursor.execute("SELECT kid, key FROM keys ORDER BY exp DESC")
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp DESC", (current_time,))
    rows = cursor.fetchall()
    conn.close()
    return rows

# Retrieve the latest key, with an option to include expired keys
def get_latest_key(include_expired=True):  # produced in part with ChatGPT
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    if include_expired:
        cursor.execute("SELECT kid, key, exp FROM keys ORDER BY exp DESC LIMIT 1")
    else:
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1", (current_time,))
    row = cursor.fetchone()
    conn.close()
    if row:
        kid, combined_data, exp = row
        
        # Split the combined data into IV and encrypted key
        iv = combined_data[:24]  # First 24 characters (16 bytes Base64 encoded)
        encrypted_key = combined_data[24:]  # Remaining characters
        
        # Decrypt the key
        decrypted_key = decrypt_private_key(iv, encrypted_key)
        return kid, decrypted_key, exp
    return None

# Retrieve the latest expired key
def get_latest_expired_key():  # produced in part with ChatGPT
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
    row = cursor.fetchone()
    conn.close()
    if row:
        kid, encrypted_key, exp = row
        # Assuming the first 16 bytes of the encrypted_key are the IV
        iv = encrypted_key[:16]  # Extract the IV
        encrypted_key = encrypted_key[16:]  # Extract the actual encrypted key
        decrypted_key = decrypt_private_key(iv, encrypted_key)  # Decrypt the key
        return kid, decrypted_key, exp
    
    return None

# Generate a new RSA key, store it in the database with an expiration time
def generate_and_store_key(expiration_hours):  # produced in part with ChatGPT
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=expiration_hours)).timestamp())
    store_key(pem, exp)
    return pem, key

def log_auth_request(request_ip, user_id):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)''', (request_ip, user_id))
    conn.commit()
    conn.close()

############### End Database Code ################ 

# Start the database and generate an initial key
init_db()
pem, private_key = generate_and_store_key(expiration_hours=1)  # 1-hour valid key
expired_pem, expired_key = generate_and_store_key(expiration_hours=-1)  # Immediately expired key

# Convert an integer to a Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    rate_limiter = RateLimiter(max_requests=10, time_window=1)  # 10 requests per second
    # Reject all responses except GET and POST
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return
    
    def do_POST(self): # modified in part with ChatGPT
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        request_ip = self.client_address[0]  # Get the request IP address

        if parsed_path.path == "/auth":
            # Check rate limiting
            if not self.rate_limiter.is_allowed():
                self.send_response(429)  # Too Many Requests
                self.end_headers()
                self.wfile.write(b'{"error": "Too many requests. Please try again later."}')
                return
            # Get the username from the POST data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            auth_data = json.loads(post_data)
            username = auth_data.get('username')

            if not username:
                self.send_response(400)  # Bad Request
                self.end_headers()
                self.wfile.write(b'{"error": "Username is required."}')
                return
        
            # Get the latest key or expired key based on request
            if 'expired' in params:
                print("getting expired key")
                key_data = get_latest_expired_key()
            else:
                key_data = get_latest_key()
            
            if not key_data:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Error: No valid key found in database")
                return
            
            kid, key_data, exp = key_data  # Unpack the returned tuple
            headers = {
                "kid": str(kid)
            }
            token_payload = {
                "user": username,
                "exp": exp
            }
            encoded_jwt = jwt.encode(token_payload, key_data, algorithm="RS256", headers=headers)
            # Retrieve the user_id from the database based on the username
            conn = sqlite3.connect(db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            conn.close()
            if user_row:
                user_id = user_row[0]  # Get user_id from the query result
            else:
                self.send_response(401)  # Unauthorized
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid username."}')
                return
            # Log the authentication request
            log_auth_request(request_ip, user_id)
            

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        elif parsed_path.path == "/register":
            # Handle user registration
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data)

            username = user_data.get("username")
            email = user_data.get("email")

            if not username or not email:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Username and email are required."}')
                return

            # Generate a secure password using UUIDv4
            password = str(uuid.uuid4())

            # Hash the password using Argon2
            hashed_password = ph.hash(password)

            # Store the user details and hashed password in the database
            conn = sqlite3.connect(db_name)
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)''',
                               (username, hashed_password, email))
                conn.commit()
                self.send_response(201)  # Created
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"password": password}), "utf-8"))
            except sqlite3.IntegrityError:
                self.send_response(409)  # Conflict
                self.end_headers()
                self.wfile.write(b'{"error": "Username or email already exists."}')
            finally:
                conn.close()
            return
        
        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self): # modified in part with ChatGPT
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            keys = {"keys": []}
            for kid, key_data in get_all_keys():
                # Load the key and get its public components
                private_key = serialization.load_pem_private_key(key_data, password=None)
                numbers = private_key.public_key().public_numbers()

                # Append each key's public components to the keys list
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

# Start server
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
