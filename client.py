"""
Key Features:
- Automatic RSA keypair generation and loading
- Hybrid encryption: RSA for key exchange, AES-EAX for message encryption
- Callback-based architecture for GUI integration
- Thread-safe message handling
- Automatic public key exchange with other users

Architecture:
- EncryptionManager: Static methods for all cryptographic operations
- ChatClient: Main client class handling network I/O and encryption
- Callbacks connect backend events to GUI without tight coupling

Example Usage:
    >>> client = ChatClient("alice")
    >>> client.on_message_received = lambda s, m, t: print(f"{s}: {m}")
    >>> client.connect("password123")
    >>> client.send_message("bob", "Hello, Bob!")
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import socket
import threading
import os
from typing import Callable, Optional, Dict, List
from datetime import datetime


class EncryptionManager:
    """
    Provides static methods for hybrid encryption operations.
    
    This class implements a hybrid encryption scheme:
    - RSA (2048-bit) with OAEP padding for key exchange
    - AES (128-bit) in EAX mode for message encryption and authentication
    
    The hybrid approach allows secure key exchange (RSA) combined with
    fast symmetric encryption (AES) for actual message content.
    """
    
    @staticmethod
    def encrypt_session_key(aes_key: bytes, public_key: RSA.RsaKey) -> bytes:
        """
        Encrypt an AES session key using RSA public key encryption.
        
        This allows secure transmission of the symmetric key over an insecure channel.
        Uses PKCS#1 OAEP padding for security against chosen ciphertext attacks.
        
        Args:
            aes_key: 16-byte AES key to encrypt
            public_key: Recipient's RSA public key
            
        Returns:
            Encrypted session key as bytes (256 bytes for 2048-bit RSA)
            
        Example:
            >>> aes_key = get_random_bytes(16)
            >>> public_key = RSA.generate(2048).publickey()
            >>> encrypted = EncryptionManager.encrypt_session_key(aes_key, public_key)
            >>> len(encrypted)
            256
        """
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_cipher_rsa = cipher_rsa.encrypt(aes_key)
        return encrypted_cipher_rsa
    
    @staticmethod
    def decrypt_session_key(encrypted_aes_key: bytes, private_key: RSA.RsaKey) -> bytes:
        """
        Decrypt an RSA-encrypted AES session key.
        
        Args:
            encrypted_aes_key: Encrypted session key (256 bytes for 2048-bit RSA)
            private_key: Your RSA private key
            
        Returns:
            Decrypted AES key (16 bytes)
            
        Example:
            >>> key = RSA.generate(2048)
            >>> aes_key = get_random_bytes(16)
            >>> encrypted = EncryptionManager.encrypt_session_key(aes_key, key.publickey())
            >>> decrypted = EncryptionManager.decrypt_session_key(encrypted, key)
            >>> aes_key == decrypted
            True
        """
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_aes_key)
    
    @staticmethod
    def encrypt_message(user_text: str, aes_key: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt a plaintext message using AES in EAX mode.
        
        EAX mode provides both encryption and authentication (AEAD), protecting
        against tampering and ensuring message integrity.
        
        Args:
            user_text: Plaintext message to encrypt
            aes_key: 16-byte AES session key
            
        Returns:
            Tuple of (ciphertext, nonce, authentication_tag)
            - ciphertext: Encrypted message content
            - nonce: 16-byte random nonce (must be unique per message)
            - authentication_tag: 16-byte MAC for integrity verification
            
        Example:
            >>> aes_key = get_random_bytes(16)
            >>> ct, nonce, tag = EncryptionManager.encrypt_message("Hello", aes_key)
            >>> len(nonce), len(tag)
            (16, 16)
        """
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, integrity = cipher_aes.encrypt_and_digest(user_text.encode())
        return ciphertext, cipher_aes.nonce, integrity

    @staticmethod
    def decrypt_message(ciphertext: bytes, nonce: bytes, integrity: bytes, aes_key: bytes) -> str:
        """
        Decrypt and verify an AES-EAX encrypted message.
        
        Args:
            ciphertext: Encrypted message content
            nonce: 16-byte nonce used during encryption
            integrity: 16-byte authentication tag
            aes_key: 16-byte AES session key
            
        Returns:
            Decrypted plaintext message
            
        Raises:
            ValueError: If authentication tag verification fails (message tampered)
            
        Example:
            >>> aes_key = get_random_bytes(16)
            >>> ct, nonce, tag = EncryptionManager.encrypt_message("Secret", aes_key)
            >>> EncryptionManager.decrypt_message(ct, nonce, tag, aes_key)
            'Secret'
        """
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_cipher_aes = cipher_aes.decrypt_and_verify(ciphertext, integrity).decode()
        return decrypted_cipher_aes


class ChatClient:
    """
    Backend client for encrypted messaging.
    
    Handles all encryption, decryption, and network communication with the server.
    Uses a callback-based design to notify the GUI layer of events without creating
    tight coupling between backend and UI code.
    
    Attributes:
        username: This client's username
        server_ip: IP address of the chat server
        server_port: Port number of the chat server
        socket: TCP socket for server connection
        aes_keys: Dict mapping usernames to their AES session keys
        user_public_keys: Dict mapping usernames to their RSA public keys
        pending_messages: Messages waiting for recipient's public key
        online_users: List of currently connected users
        private_key: This client's RSA private key
        public_key: This client's RSA public key
        
    Callbacks (set by GUI):
        on_message_received(sender, message, timestamp): New message arrived
        on_system_message(message): System notification
        on_user_connected(username): User came online or key received
        on_user_disconnected(username): User went offline
        on_connection_established(): Connected to server successfully
        on_error(error_message): Error occurred
        on_online_users_updated(user_list): User list changed
        on_typing_indicator(username): User is typing
    """
    
    def __init__(self, username: str, server_ip: str = "10.192.127.137", server_port: int = 5000):
        """
        Initialize a new chat client.
        
        Args:
            username: Unique username for this client
            server_ip: IP address of chat server (default: "10.192.127.137")
            server_port: Port number of chat server (default: 5000)
        """
        self.username = username
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Encryption key storage
        self.aes_keys: Dict[str, bytes] = {}  # username -> AES session key
        self.user_public_keys: Dict[str, RSA.RsaKey] = {}  # username -> RSA public key
        self.pending_messages: Dict[str, str] = {}  # username -> queued message
        self.online_users: List[str] = []  # List of online usernames
        
        # RSA key file paths (stored locally per user)
        self.private_file = f"{username}_private.pem"
        self.public_file = f"{username}_public.pem"
        
        # Load or generate RSA keypair
        self.check_or_generate_keys()
        self.private_key = RSA.import_key(open(self.private_file, "rb").read())
        self.public_key = RSA.import_key(open(self.public_file, "rb").read())
        
        # Callback functions (GUI sets these after initialization)
        self.on_message_received: Optional[Callable[[str, str, datetime], None]] = None
        self.on_system_message: Optional[Callable[[str], None]] = None
        self.on_user_connected: Optional[Callable[[str], None]] = None
        self.on_user_disconnected: Optional[Callable[[str], None]] = None
        self.on_connection_established: Optional[Callable[[], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_auth_required: Optional[Callable[[bool], str]] = None
        self.on_online_users_updated: Optional[Callable[[List[str]], None]] = None
        self.on_typing_indicator: Optional[Callable[[str], None]] = None
        
        # Thread management
        self._running = False  # Flag to control receive thread
        self._receive_thread = None  # Background thread for receiving messages
        self._authenticated = False  # Authentication status

    def check_or_generate_keys(self):
        """
        Ensure this client has an RSA keypair, generating one if needed.
        
        Checks for existing key files. If not found, generates a new 2048-bit
        RSA keypair and saves it to PEM files for future use.
        
        Side Effects:
            Creates {username}_private.pem and {username}_public.pem files
        """
        # Check if both key files exist
        if not (os.path.exists(self.private_file) and os.path.exists(self.public_file)):
            print(f"Generating RSA key pair for user '{self.username}'...")
            
            # Generate 2048-bit RSA keypair
            key = RSA.generate(2048)
            
            # Save private key
            with open(self.private_file, "wb") as f:
                f.write(key.export_key())
            
            # Save public key
            with open(self.public_file, "wb") as f:
                f.write(key.publickey().export_key())
            
            print(f"Keys generated and saved.")

    def connect(self, password: str) -> bool:
        """
        Connect to the server and authenticate.
        
        Performs the following steps:
        1. Establish TCP connection to server
        2. Receive authentication prompt
        3. Send credentials (username and password)
        4. Handle authentication response (login or registration)
        5. Send public RSA key to server
        6. Start background thread for receiving messages
        
        Args:
            password: User's password for authentication
            
        Returns:
            True if connection and authentication successful, False otherwise
            
        Side Effects:
            - Establishes socket connection
            - Starts receive thread
            - Calls on_connection_established callback on success
            - Calls on_error callback on failure
        """
        try:
            # Step 1: Connect to server
            self.socket.connect((self.server_ip, self.server_port))
            
            # Step 2: Wait for authentication prompt
            auth_prompt = self.socket.recv(1024).strip()
            if auth_prompt != b"AUTH_REQUIRED":
                if self.on_error:
                    self.on_error("Unexpected server response")
                return False
            
            # Step 3: Send authentication credentials
            auth_msg = b"AUTH|" + self.username.encode() + b"|" + password.encode() + b"\n"
            self.socket.sendall(auth_msg)
            
            # Step 4: Wait for authentication result
            auth_response = self.socket.recv(1024).strip()
            
            if auth_response.startswith(b"AUTH_SUCCESS"):
                self._authenticated = True
                
                # Check if this was a new registration or existing login
                if b"REGISTERED" in auth_response:
                    if self.on_system_message:
                        self.on_system_message("Account created successfully!")
                elif b"LOGIN" in auth_response:
                    if self.on_system_message:
                        self.on_system_message("Logged in successfully!")
                        
            elif auth_response.startswith(b"AUTH_FAILED"):
                # Extract error message if provided
                error_msg = auth_response.decode().split("|", 1)[1] if b"|" in auth_response else "Authentication failed"
                if self.on_error:
                    self.on_error(error_msg)
                return False
            
            # Step 5: Send public RSA key to server
            with open(self.public_file, "rb") as f:
                public_key_bytes = f.read()
            
            # Encode key as base64 for safe transmission
            encoded_key = base64.b64encode(public_key_bytes)
            self.socket.sendall(b"PUBKEY|" + self.username.encode() + b"|" + encoded_key + b"\n")
            
            # Step 6: Start background thread to receive messages
            self._running = True
            self._receive_thread = threading.Thread(target=self._receive_messages, daemon=True)
            self._receive_thread.start()
            
            # Notify GUI of successful connection
            if self.on_connection_established:
                self.on_connection_established()
                
            return True
            
        except Exception as e:
            if self.on_error:
                self.on_error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """
        Cleanly disconnect from the server.
        
        Stops the receive thread and closes the socket connection.
        Safe to call even if not connected.
        """
        self._running = False
        try:
            self.socket.close()
        except:
            pass  # Ignore errors during cleanup

    def send_message(self, recipient: str, message: str):
        """
        Encrypt and send a message to another user.
        
        Process:
        1. Check if we have recipient's public key (request if not)
        2. Generate or retrieve AES session key for this user
        3. If new session, encrypt and send session key
        4. Encrypt message with AES-EAX
        5. Send encrypted message to server for forwarding
        
        Args:
            recipient: Username of message recipient
            message: Plaintext message to send
            
        Side Effects:
            - May request recipient's public key from server
            - Queues message if public key not available
            - Sends encrypted data over network
            - Calls on_system_message or on_error callbacks
        """
        # Step 1: Verify we have recipient's public key
        if recipient not in self.user_public_keys:
            # Request public key from server
            self._request_public_key(recipient)
            
            # Queue message to send after key arrives
            self.pending_messages[recipient] = message
            
            if self.on_system_message:
                self.on_system_message(f"Requesting public key for {recipient}...")
            return
        
        try:
            # Step 2: Get or create AES session key for this recipient
            if recipient not in self.aes_keys:
                # Generate new 128-bit AES key
                aes_key = get_random_bytes(16)
                self.aes_keys[recipient] = aes_key
                
                # Step 3: Encrypt session key with recipient's RSA public key
                encrypted_key_raw = EncryptionManager.encrypt_session_key(
                    aes_key, 
                    self.user_public_keys[recipient]
                )
                
                # Encode for transmission
                encrypted_key_encoded = base64.b64encode(encrypted_key_raw)
                
                # Send encrypted session key to recipient
                self.socket.sendall(
                    b"SESSIONKEY|" + recipient.encode() + b"|" + encrypted_key_encoded + b"\n"
                )
            
            # Step 4: Encrypt message with AES
            aes_key = self.aes_keys[recipient]
            ciphertext, nonce, integrity = EncryptionManager.encrypt_message(message, aes_key)
            
            # Step 5: Combine encrypted components (nonce + tag + ciphertext)
            encrypted_data = nonce + integrity + ciphertext
            encrypted_data_encoded = base64.b64encode(encrypted_data)
            
            # Send encrypted message to server for forwarding
            msg_to_send = b"MSG|" + recipient.encode() + b"|" + encrypted_data_encoded + b"\n"
            self.socket.sendall(msg_to_send)
            
        except Exception as e:
            if self.on_error:
                self.on_error(f"Failed to send message: {e}")

    def send_typing_indicator(self, recipient: str):
        """
        Send a typing notification to another user.
        
        Args:
            recipient: Username to notify of typing activity
        """
        try:
            self.socket.sendall(b"TYPING|" + recipient.encode() + b"\n")
        except Exception as e:
            if self.on_error:
                self.on_error(f"Failed to send typing indicator: {e}")

    def _request_public_key(self, username: str):
        """
        Request another user's public RSA key from the server.
        
        Internal method called automatically when trying to message a user
        whose public key we don't have yet.
        
        Args:
            username: Username whose public key is needed
        """
        try:
            self.socket.sendall(b"REQKEY|" + username.encode() + b"\n")
        except Exception as e:
            if self.on_error:
                self.on_error(f"Failed to request public key: {e}")

    def _receive_messages(self):
        """
        Background thread that continuously receives and processes messages.
        
        Maintains a buffer for incomplete messages and processes complete messages
        (delimited by newlines) as they arrive. Runs until self._running is False.
        
        Message types handled:
        - PUBKEY: Public key announcements
        - SESSIONKEY: Encrypted AES session keys
        - MSG: Encrypted messages
        - USERLIST: Online user list updates
        - TYPING: Typing indicators
        """
        buffer = b""  # Buffer for incomplete messages
        
        while self._running:
            try:
                # Receive data from server (up to 8KB at a time)
                data = self.socket.recv(8192)
                
                if not data:
                    # Connection closed by server
                    if self.on_system_message:
                        self.on_system_message("Server closed connection.")
                    break
                    
                buffer += data
                
                # Process all complete messages in buffer (split by newline)
                while b"\n" in buffer:
                    message, buffer = buffer.split(b"\n", 1)
                    self._process_message(message)
                    
            except Exception as e:
                # Only report errors if we're supposed to be running
                if self._running:
                    if self.on_error:
                        self.on_error(f"Error receiving message: {e}")
                break

    def _process_message(self, message: bytes):
        """
        Process a single complete message received from the server.
        
        Routes the message to the appropriate handler based on message type prefix.
        
        Args:
            message: Complete message bytes (without trailing newline)
        """
        try:
            # Route to appropriate handler based on message prefix
            if message.startswith(b"PUBKEY|"):
                self._handle_public_key(message)
            elif message.startswith(b"SESSIONKEY|"):
                self._handle_session_key(message)
            elif message.startswith(b"MSG|"):
                self._handle_encrypted_message(message)
            elif message.startswith(b"USERLIST|"):
                self._handle_user_list(message)
            elif message.startswith(b"TYPING|"):
                self._handle_typing_indicator(message)
            else:
                # Unknown message format
                if self.on_system_message:
                    self.on_system_message("Received unknown message format.")
                    
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error processing message: {e}")

    def _handle_public_key(self, message: bytes):
        """
        Handle receiving another user's RSA public key.
        
        Format: PUBKEY|username|base64_encoded_key
        
        Stores the public key and sends any pending messages to that user.
        
        Args:
            message: Public key message bytes
        """
        try:
            # Parse message: PUBKEY|sender|encoded_key
            _, sender, encoded_key = message.split(b"|", 2)
            sender = sender.decode()
            
            # Decode and import the RSA public key
            public_key_bytes = base64.b64decode(encoded_key)
            public_key = RSA.import_key(public_key_bytes)
            
            # Store public key for future message encryption
            self.user_public_keys[sender] = public_key
            
            # Notify GUI that user is now available
            if self.on_user_connected:
                self.on_user_connected(sender)
            
            # Send any messages that were waiting for this user's public key
            if sender in self.pending_messages:
                pending_message = self.pending_messages.pop(sender)
                self.send_message(sender, pending_message)
                
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error processing public key: {e}")

    def _handle_session_key(self, message: bytes):
        """
        Handle receiving an encrypted AES session key from another user.
        
        Format: SESSIONKEY|sender|base64_encrypted_aes_key
        
        Decrypts the session key using our private RSA key and stores it for
        decrypting future messages from this sender.
        
        Args:
            message: Session key message bytes
        """
        try:
            # Parse message: SESSIONKEY|sender|encrypted_key
            _, sender, encrypted_aes_key_encoded = message.split(b"|", 2)
            sender = sender.decode()
            
            # Decode the encrypted AES key
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_encoded)
            
            # Decrypt using our private RSA key
            aes_key = EncryptionManager.decrypt_session_key(
                encrypted_aes_key, 
                self.private_key
            )
            
            # Store for decrypting messages from this sender
            self.aes_keys[sender] = aes_key
            
            # Notify GUI that secure channel is established
            if self.on_system_message:
                self.on_system_message(f"Secure channel established with {sender}")
                
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error decrypting session key from {sender}: {e}")

    def _handle_encrypted_message(self, message: bytes):
        """
        Handle receiving and decrypting an encrypted message.
        
        Format: MSG|sender|base64_encrypted_data
        
        The encrypted data contains: nonce (16) + integrity_tag (16) + ciphertext
        
        Args:
            message: Encrypted message bytes
        """
        try:
            # Parse message: MSG|sender|encrypted_data
            _, sender, encrypted_data_encoded = message.split(b"|", 2)
            sender = sender.decode()
            
            # Check if we have the session key for this sender
            aes_key = self.aes_keys.get(sender)
            if not aes_key:
                if self.on_system_message:
                    self.on_system_message(f"No session key for {sender}. Cannot decrypt.")
                return
            
            # Decode the base64 encrypted data
            encrypted_data = base64.b64decode(encrypted_data_encoded)
            
            # Extract components: nonce (16 bytes) + tag (16 bytes) + ciphertext
            nonce = encrypted_data[:16]
            integrity = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            # Decrypt the message
            decrypted_message = EncryptionManager.decrypt_message(
                ciphertext, nonce, integrity, aes_key
            )
            
            # Notify GUI of received message
            if self.on_message_received:
                self.on_message_received(sender, decrypted_message, datetime.now())
                
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error decrypting message from {sender}: {e}")

    def _handle_user_list(self, message: bytes):
        """
        Handle receiving an updated list of online users.
        
        Format: USERLIST|user1,user2,user3
        
        Detects disconnections by comparing with previous user list.
        
        Args:
            message: User list message bytes
        """
        try:
            # Parse message: USERLIST|comma_separated_users
            _, users_str = message.split(b"|", 1)
            users_str = users_str.decode()
            
            # Parse user list (may be empty)
            if users_str:
                new_users = users_str.split(",")
            else:
                new_users = []
            
            # Detect disconnections by comparing sets
            old_users = set(self.online_users)
            current_users = set(new_users)
            disconnected = old_users - current_users
            
            # Notify GUI of each disconnection
            for user in disconnected:
                if self.on_user_disconnected:
                    self.on_user_disconnected(user)
            
            # Update stored user list
            self.online_users = new_users
            
            # Notify GUI of updated list
            if self.on_online_users_updated:
                self.on_online_users_updated(self.online_users)
                
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error processing user list: {e}")

    def _handle_typing_indicator(self, message: bytes):
        """
        Handle receiving a typing indicator from another user.
        
        Format: TYPING|sender
        
        Args:
            message: Typing indicator message bytes
        """
        try:
            # Parse message: TYPING|sender
            _, sender = message.split(b"|", 1)
            sender = sender.decode()
            
            # Notify GUI to show typing indicator
            if self.on_typing_indicator:
                self.on_typing_indicator(sender)
                
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error processing typing indicator: {e}")

    def get_connected_users(self) -> List[str]:
        """
        Get list of users whose public keys we have.
        
        Returns:
            List of usernames we can send encrypted messages to
        """
        return list(self.user_public_keys.keys())


def main():
    """
    Command-line interface for testing the backend independently.
    
    Demonstrates how to use ChatClient with simple CLI callbacks.
    Type 'recipient:message' to send, or 'quit' to exit.
    """
    username = input("Enter your username: ")
    password = input("Enter password: ")
    
    # Create client instance
    client = ChatClient(username)
    
    # Set up CLI callbacks
    def on_message(sender, message, timestamp):
        print(f"\n[{sender}] ({timestamp.strftime('%H:%M')}): {message}")
        print("> ", end="", flush=True)
    
    def on_system(message):
        print(f"\n[System]: {message}")
        print("> ", end="", flush=True)
    
    def on_user_connected(user):
        print(f"\n[System]: {user} is now available")
        print("> ", end="", flush=True)
    
    def on_user_disconnected(user):
        print(f"\n[System]: {user} disconnected")
        print("> ", end="", flush=True)
    
    def on_connected():
        print(f"\n[System]: Connected to server at {client.server_ip}:{client.server_port}")
        print("Type 'recipient:message' to send, or 'quit' to exit.")
        print("> ", end="", flush=True)
    
    def on_error(error):
        print(f"\n[Error]: {error}")
        print("> ", end="", flush=True)
    
    def on_users_updated(users):
        print(f"\n[Online]: {', '.join(users)}")
        print("> ", end="", flush=True)
    
    # Wire up callbacks
    client.on_message_received = on_message
    client.on_system_message = on_system
    client.on_user_connected = on_user_connected
    client.on_user_disconnected = on_user_disconnected
    client.on_connection_established = on_connected
    client.on_error = on_error
    client.on_online_users_updated = on_users_updated
    
    # Attempt connection
    if not client.connect(password):
        print("Failed to connect to server.")
        return
    
    # Main input loop
    while True:
        try:
            input_data = input("> ")
            
            if input_data.lower() == "quit":
                break
            
            # Parse input as "recipient:message"
            if ":" in input_data:
                recipient_user, message = input_data.split(":", 1)
                client.send_message(recipient_user.strip(), message.strip())
            else:
                print("Invalid format. Use 'recipient:message'.")
                
        except KeyboardInterrupt:
            break
    
    # Clean up
    client.disconnect()
    print("\nDisconnected.")


if __name__ == "__main__":
    main()