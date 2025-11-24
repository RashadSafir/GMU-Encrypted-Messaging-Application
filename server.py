"""
A multi-threaded TCP server that handles user authentication, encrypted messaging,
and real-time communication between clients.

Features:
- User registration and authentication with password hashing
- RSA public key exchange for end-to-end encryption setup
- Message forwarding between authenticated users
- SQLite database for user credentials and message history
- Automatic cleanup of old messages (2 hour retention)
- Real-time online user list broadcasting
- Typing indicators

Architecture:
- Main server thread accepts new connections
- Each client handled by dedicated thread with message buffering
- Thread-safe client management with locks
- Database operations for persistent storage
"""

from Crypto.PublicKey import RSA
import socket
import threading
import base64
import sqlite3
import hashlib
import time
from datetime import datetime, timedelta

# Thread-safe storage
clients = {}  # username -> socket
user_public_keys = {}  # username -> public_key_bytes
clients_lock = threading.Lock()
authenticated_users = set()  # Users who have successfully authenticated

# Database configuration
DB_FILE = "chat_server.db"


def init_database():
    """
    Initialize SQLite database with required tables and indexes.
    
    Creates:
    - users table: Stores username, password hash, and registration timestamp
    - messages table: Stores encrypted messages with sender, recipient, and timestamp
    - Index on messages.timestamp for efficient cleanup queries
    
    Returns:
        None
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Messages table (for history)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            encrypted_content BLOB NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender) REFERENCES users(username),
            FOREIGN KEY (recipient) REFERENCES users(username)
        )
    ''')
    
    # Create index for faster message queries
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_messages_timestamp 
        ON messages(timestamp)
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized.")


def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Hexadecimal string representation of the password hash
        
    Example:
        >>> hash_password("mypassword")
        '89e01536ac207279409d4de1e5253e01f4a1769e696db0d6062ca9b8f56767c8'
    """
    return hashlib.sha256(password.encode()).hexdigest()


def register_user(username: str, password: str) -> bool:
    """
    Register a new user in the database.
    
    Args:
        username: Unique username for the new user
        password: Plain text password (will be hashed before storage)
        
    Returns:
        True if registration successful, False if username already exists
        
    Example:
        >>> register_user("alice", "password123")
        True
        >>> register_user("alice", "different_password")
        False
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # User already exists


def authenticate_user(username: str, password: str) -> bool:
    """
    Verify user credentials against stored hash.
    
    Args:
        username: Username to authenticate
        password: Plain text password to verify
        
    Returns:
        True if credentials are valid, False otherwise
        
    Example:
        >>> authenticate_user("alice", "password123")
        True
        >>> authenticate_user("alice", "wrong_password")
        False
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    password_hash = hash_password(password)
    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0] == password_hash:
        return True
    return False


def user_exists(username: str) -> bool:
    """
    Check if a username exists in the database.
    
    Args:
        username: Username to check
        
    Returns:
        True if user exists, False otherwise
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def save_message(sender: str, recipient: str, encrypted_content: bytes):
    """
    Save an encrypted message to the database.
    
    Args:
        sender: Username of the message sender
        recipient: Username of the message recipient
        encrypted_content: Base64-encoded encrypted message data
        
    Returns:
        None
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (sender, recipient, encrypted_content) VALUES (?, ?, ?)",
        (sender, recipient, encrypted_content)
    )
    conn.commit()
    conn.close()


def cleanup_old_messages():
    """
    Delete messages older than 2 hours from the database.
    
    This function is called periodically by a background thread to maintain
    database size and privacy.
    
    Returns:
        None
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cutoff_time = datetime.now() - timedelta(hours=2)
    cursor.execute(
        "DELETE FROM messages WHERE timestamp < ?",
        (cutoff_time,)
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        print(f"Cleaned up {deleted} old messages.")


def broadcast_user_list():
    """
    Send updated online user list to all connected clients.
    
    Format: USERLIST|user1,user2,user3\n
    
    Thread-safe: Uses clients_lock to prevent race conditions.
    
    Returns:
        None
    """
    with clients_lock:
        online_users = list(clients.keys())
        user_list_msg = b"USERLIST|" + ",".join(online_users).encode() + b"\n"
        for client_socket in clients.values():
            try:
                client_socket.sendall(user_list_msg)
            except:
                pass


def handle_client(client_socket):
    """
    Handle all communication with a single client.
    
    This function runs in its own thread and manages:
    1. Authentication (login or registration)
    2. Public key exchange
    3. Message forwarding
    4. Typing indicators
    5. Key requests
    
    Protocol Messages:
    - AUTH|username|password - Client authentication
    - PUBKEY|username|base64_key - Public key announcement
    - REQKEY|username - Request another user's public key
    - SESSIONKEY|recipient|encrypted_key - Forward encrypted session key
    - MSG|recipient|encrypted_data - Forward encrypted message
    - TYPING|recipient - Typing indicator
    
    Args:
        client_socket: Connected socket object for this client
        
    Returns:
        None
    """
    username = None
    buffer = b""  # Buffer for incomplete messages
    
    try:
        # ============ Authentication Phase ============
        client_socket.sendall(b"AUTH_REQUIRED\n")
        
        auth_data = client_socket.recv(8192).strip()
        if not auth_data.startswith(b"AUTH|"):
            client_socket.sendall(b"AUTH_FAILED|Invalid format\n")
            return
        
        _, auth_username, auth_password = auth_data.split(b"|", 2)
        username = auth_username.decode()
        password = auth_password.decode()
        
        # Check if user exists
        if user_exists(username):
            # Existing user - verify password
            if authenticate_user(username, password):
                client_socket.sendall(b"AUTH_SUCCESS|LOGIN\n")
            else:
                client_socket.sendall(b"AUTH_FAILED|Invalid password\n")
                return
        else:
            # New user - register
            if register_user(username, password):
                client_socket.sendall(b"AUTH_SUCCESS|REGISTERED\n")
            else:
                client_socket.sendall(b"AUTH_FAILED|Registration failed\n")
                return
        
        print(f"{username} authenticated successfully.")
        
        # ============ Public Key Exchange ============
        pubkey_data = client_socket.recv(8192).strip()
        if pubkey_data.startswith(b"PUBKEY|"):
            _, pub_username, pubkey_bytes_encoded = pubkey_data.split(b"|", 2)
            publickey_bytes = base64.b64decode(pubkey_bytes_encoded)
            user_public_keys[username] = publickey_bytes
            
            with clients_lock:
                clients[username] = client_socket
                authenticated_users.add(username)
            
            print(f"{username} connected and sent public key.")
            
            # Broadcast updated user list
            broadcast_user_list()
        
        # ============ Main Message Loop ============
        while True:
            data = client_socket.recv(8192)
            if not data:
                break
            
            buffer += data
            
            # Process all complete messages in buffer (delimited by \n)
            while b"\n" in buffer:
                message_data, buffer = buffer.split(b"\n", 1)
                
                # ---- Public Key Request ----
                if message_data.startswith(b"REQKEY|"):
                    _, requested_user = message_data.split(b"|", 1)
                    requested_user = requested_user.decode()
                    
                    if requested_user in user_public_keys:
                        encoded_key = base64.b64encode(user_public_keys[requested_user])
                        client_socket.sendall(
                            b"PUBKEY|" + requested_user.encode() + b"|" + encoded_key + b"\n"
                        )
                        print(f"Sent public key of {requested_user} to {username}.")
                    else:
                        print(f"Public key for {requested_user} not found.")
                    continue
                
                # ---- Session Key Forwarding ----
                elif message_data.startswith(b"SESSIONKEY|"):
                    try:
                        _, end_username, encrypted_key = message_data.split(b"|", 2)
                        end_username = end_username.decode()
                        
                        forwarded_message = b"SESSIONKEY|" + username.encode() + b"|" + encrypted_key + b"\n"
                        with clients_lock:
                            if end_username in clients:
                                clients[end_username].sendall(forwarded_message)
                                print(f"Forwarded SESSIONKEY to {end_username} from {username}.")
                    except Exception as e:
                        print(f"Error processing SESSIONKEY: {e}")
                    continue
                
                # ---- Encrypted Message Forwarding ----
                elif message_data.startswith(b"MSG|"):
                    try:
                        _, end_username_bytes, encrypted_msg = message_data.split(b"|", 2)
                        end_username = end_username_bytes.decode()
                        
                        # Save message to database
                        save_message(username, end_username, encrypted_msg)
                        
                        forwarded_message = b"MSG|" + username.encode() + b"|" + encrypted_msg + b"\n"
                        with clients_lock:
                            if end_username in clients:
                                clients[end_username].sendall(forwarded_message)
                                print(f"Forwarded message from {username} to {end_username}.")
                            else:
                                print(f"User {end_username} not online. Message saved to history.")
                    except Exception as e:
                        print(f"Error processing MSG: {e}")
                    continue
                
                # ---- Typing Indicator ----
                elif message_data.startswith(b"TYPING|"):
                    try:
                        _, recipient = message_data.split(b"|", 1)
                        recipient = recipient.decode()
                        with clients_lock:
                            if recipient in clients:
                                clients[recipient].sendall(b"TYPING|" + username.encode() + b"\n")
                    except Exception as e:
                        print(f"Error forwarding typing indicator: {e}")
                    continue
            
    except Exception as e:
        print(f"Client {username} error: {e}")
    finally:
        # ============ Cleanup ============
        with clients_lock:
            if username in clients:
                clients.pop(username, None)
                authenticated_users.discard(username)
        client_socket.close()
        print(f"{username} disconnected.")
        
        # Broadcast updated user list
        broadcast_user_list()


def cleanup_task():
    """
    Background task that periodically cleans up old messages.
    
    Runs every hour and removes messages older than 2 hours.
    This runs as a daemon thread and will exit when the main program exits.
    
    Returns:
        None
    """
    while True:
        time.sleep(3600)  # Run every hour
        cleanup_old_messages()


def start_server(host="0.0.0.0", port=5000):
    """
    Start the chat server and begin accepting connections.
    
    This function:
    1. Initializes the database
    2. Starts the cleanup background thread
    3. Creates a TCP socket and binds to the specified address
    4. Accepts connections and spawns handler threads
    
    Args:
        host: IP address to bind to (default: 0.0.0.0 for all interfaces)
        port: Port number to listen on (default: 5000)
        
    Returns:
        None (runs indefinitely until interrupted)
        
    Example:
        >>> start_server("127.0.0.1", 5000)
        Database initialized.
        Server listening on 127.0.0.1:5000
        Authentication enabled. Database: chat_server.db
    """
    init_database()
    
    # Start cleanup task
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server listening on {host}:{port}")
    print("Authentication enabled. Database: chat_server.db")
    
    while True:
        client_socket, address = server_socket.accept()
        print(f"Accepted connection from {address}")
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_server()