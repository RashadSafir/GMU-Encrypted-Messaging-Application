"""
- Modern UI
- Three theme options (default, dark, light)
- Real-time encrypted messaging with message bubbles
- Online user list with unread message indicators

Architecture:
- ChatSignals: Qt signals for thread-safe GUI updates
- LoginPage: Authentication and server connection page
- ChatPage: Main messaging interface
- MainWindow: Application container managing page transitions

The GUI connects to the ChatClient backend via callbacks, maintaining separation
between UI and business logic.
"""

import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QListWidget, QMessageBox, QScrollArea,
    QListWidgetItem, QStackedWidget, QFrame, QSizePolicy, QSpacerItem
)
from PyQt6.QtCore import pyqtSignal, QObject, pyqtSlot, QTimer, Qt
from PyQt6.QtGui import QFont, QColor, QPalette
from client import ChatClient
from datetime import datetime, timedelta
from typing import Dict


class ChatSignals(QObject):
    """
    Qt signals for thread-safe communication between backend and GUI.
    
    Since the ChatClient receives messages in a background thread, we need
    Qt signals to safely update the GUI from those threads. All backend
    callbacks emit these signals, which are then handled by GUI slots running
    in the main Qt thread.
    
    Signals:
        message_received(sender, message, timestamp): New encrypted message arrived
        system_message(message): System notification or status update
        user_connected(username): User came online or public key received
        user_disconnected(username): User went offline
        connection_established(): Successfully connected to server
        error_occurred(error): Error message to display
        online_users_updated(user_list): Updated list of online users
        typing_indicator(username): User is currently typing
    """
    message_received = pyqtSignal(str, str, object)  # sender, message, timestamp
    system_message = pyqtSignal(str)
    user_connected = pyqtSignal(str)
    user_disconnected = pyqtSignal(str)
    connection_established = pyqtSignal()
    error_occurred = pyqtSignal(str)
    online_users_updated = pyqtSignal(list)
    typing_indicator = pyqtSignal(str)


class LoginPage(QWidget):
    """    
    Handles user authentication including:
    - Username input
    - Password input (masked)
    - Server IP address configuration
    - Theme selection (inherited from parent)
    
    Features:
    - Automatic account creation for new users
    - Input validation before submission
    - Enter key support for quick login
    
    Signals:
        login_successful(username, password, server_ip): Emitted when user submits valid credentials
    """
    
    # Signal emitted when user clicks login with valid inputs
    login_successful = pyqtSignal(str, str, str)  # username, password, server_ip
    
    def __init__(self):
        """Initialize the login page with default theme."""
        super().__init__()
        self.theme = "default"  # Options: default, dark, light
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        """
        Create and layout all login page widgets.
        
        Layout structure:
        - Centered container with login box
        - Title and subtitle
        - Username, password, and server IP input fields
        - Info text about automatic registration
        - Login button
        """
        # Main layout with center alignment
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setLayout(main_layout)
        
        # Center container for vertical centering
        center_widget = QWidget()
        center_layout = QVBoxLayout()
        center_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        center_widget.setLayout(center_layout)
        
        # Login box
        login_box = QFrame()
        login_box.setObjectName("loginBox")  # For stylesheet targeting
        login_box.setFixedSize(480, 520)
        login_layout = QVBoxLayout()
        login_layout.setSpacing(20)
        login_layout.setContentsMargins(40, 40, 40, 40)
        login_box.setLayout(login_layout)
        
        # Title section
        title = QLabel("Welcome!")
        title.setObjectName("loginTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.addWidget(title)
        
        subtitle = QLabel("Enter your credentials to continue")
        subtitle.setObjectName("loginSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.addWidget(subtitle)
        
        login_layout.addSpacing(10)
        
        # Username field
        username_label = QLabel("USERNAME")
        username_label.setObjectName("fieldLabel")
        username_label.setFixedHeight(20)
        login_layout.addWidget(username_label)
        
        self.username_input = QLineEdit()
        self.username_input.setObjectName("loginInput")
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setFixedHeight(40)
        login_layout.addWidget(self.username_input)
        
        # Password field
        password_label = QLabel("PASSWORD")
        password_label.setObjectName("fieldLabel")
        password_label.setFixedHeight(20)
        login_layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setObjectName("loginInput")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Mask password
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setFixedHeight(40)
        login_layout.addWidget(self.password_input)
        
        # Info text about automatic registration
        info = QLabel("New user? An account will be created automatically.")
        info.setObjectName("infoText")
        info.setWordWrap(True)
        login_layout.addWidget(info)
        
        login_layout.addSpacing(10)
        
        # Login button
        self.login_btn = QPushButton("Log In")
        self.login_btn.setObjectName("loginButton")
        self.login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_btn.clicked.connect(self.attempt_login)
        login_layout.addWidget(self.login_btn)
        
        # Connect Enter key in all input fields to login action
        self.username_input.returnPressed.connect(self.attempt_login)
        self.password_input.returnPressed.connect(self.attempt_login)
        
        # Add login box to center container
        center_layout.addWidget(login_box)
        main_layout.addWidget(center_widget)
    
    def attempt_login(self):
        """
        Validate user inputs and emit login signal if valid.
        
        Validation checks:
        - Username must not be empty
        - Password must not be empty
        - Server IP must not be empty
        
        Shows warning dialog for any validation failures.
        """
        # Get and sanitize inputs
        username = self.username_input.text().strip()
        password = self.password_input.text()
        server_ip = "10.192.127.137"  # Default server IP
        
        # Validate username
        if not username:
            QMessageBox.warning(self, "Missing Information", "Please enter a username")
            return
        
        # Validate password
        if not password:
            QMessageBox.warning(self, "Missing Information", "Please enter a password")
            return
        
        # All validation passed - emit signal for MainWindow to handle
        self.login_successful.emit(username, password, server_ip)
    
    def apply_theme(self):
        """
        Apply the current theme's stylesheet to the login page.
        
        Themes:
        - default: Green and gold color scheme
        - dark: dark mode colors
        - light: light mode colors
        """
        if self.theme == "dark":
            # dark theme colors
            self.setStyleSheet("""
                QWidget {
                    background-color: #36393f;
                    color: #dcddde;
                    font-family: 'Segoe UI', Arial, sans-serif;
                }
                QFrame#loginBox {
                    background-color: #2f3136;
                    border-radius: 8px;
                }
                QLabel#loginTitle {
                    font-size: 24px;
                    font-weight: bold;
                    color: #ffffff;
                }
                QLabel#loginSubtitle {
                    font-size: 14px;
                    color: #b9bbbe;
                    margin-bottom: 10px;
                }
                QLabel#fieldLabel {
                    font-size: 11px;
                    font-weight: bold;
                    color: #b9bbbe;
                    letter-spacing: 0.5px;
                    background: none;
                    border: none;
                }
                QLineEdit#loginInput {
                    background-color: #202225;
                    border: 1px solid #202225;
                    border-radius: 4px;
                    padding: 10px;
                    color: #dcddde;
                    font-size: 14px;
                }
                QLineEdit#loginInput:focus {
                    border: 1px solid #00b0f4;
                }
                QPushButton#loginButton {
                    background-color: #5865f2;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 12px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton#loginButton:hover {
                    background-color: #4752c4;
                }
                QLabel#infoText {
                    color: #72767d;
                    font-size: 12px;
                }
            """)
        elif self.theme == "light":
            # light theme colors
            self.setStyleSheet("""
                QWidget {
                    background-color: #ffffff;
                    color: #2e3338;
                    font-family: 'Segoe UI', Arial, sans-serif;
                }
                QFrame#loginBox {
                    background-color: #f6f6f7;
                    border-radius: 8px;
                }
                QLabel#loginTitle {
                    font-size: 24px;
                    font-weight: bold;
                    color: #2e3338;
                }
                QLabel#loginSubtitle {
                    font-size: 14px;
                    color: #5c5e66;
                    margin-bottom: 10px;
                }
                QLabel#fieldLabel {
                    font-size: 11px;
                    font-weight: bold;
                    color: #5c5e66;
                    letter-spacing: 0.5px;
                    background: none;
                    border: none;
                }
                QLineEdit#loginInput {
                    background-color: #e3e5e8;
                    border: 1px solid #e3e5e8;
                    border-radius: 4px;
                    padding: 10px;
                    color: #2e3338;
                    font-size: 14px;
                }
                QLineEdit#loginInput:focus {
                    border: 1px solid #00b0f4;
                }
                QPushButton#loginButton {
                    background-color: #5865f2;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 12px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton#loginButton:hover {
                    background-color: #4752c4;
                }
                QLabel#infoText {
                    color: #747f8d;
                    font-size: 12px;
                }
            """)
        else:  # default (green and yellow theme)
            self.setStyleSheet("""
                QWidget {
                    background-color: #2d5016;
                    color: #ffeb3b;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    font-weight: bold;
                }
                QFrame#loginBox {
                    background-color: #3d6020;
                    border-radius: 8px;
                    border: 2px solid #ffeb3b;
                }
                QLabel#loginTitle {
                    font-size: 24px;
                    font-weight: bold;
                    color: #ffeb3b;
                    background: none;
                    border: none;
                }
                QLabel#loginSubtitle {
                    font-size: 14px;
                    color: #ffeb3b;
                    margin-bottom: 10px;
                    background: none;
                    border: none;
                }
                QLabel#fieldLabel {
                    font-size: 11px;
                    font-weight: bold;
                    color: #ffeb3b;
                    letter-spacing: 0.5px;
                    background: none;
                    border: none;
                    padding: 0px;
                    margin: 0px;
                }
                QLineEdit#loginInput {
                    background-color: #1a3d0f;
                    border: 2px solid #ffeb3b;
                    border-radius: 4px;
                    padding: 10px;
                    color: #ffeb3b;
                    font-size: 14px;
                    font-weight: bold;
                }
                QLineEdit#loginInput:focus {
                    border: 3px solid #ffeb3b;
                    background-color: #0f2907;
                }
                QPushButton#loginButton {
                    background-color: #ffeb3b;
                    color: #2d5016;
                    border: none;
                    border-radius: 4px;
                    padding: 12px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton#loginButton:hover {
                    background-color: #ffd700;
                }
                QLabel#infoText {
                    color: #b8d99f;
                    font-size: 12px;
                    background: none;
                    border: none;
                    font-weight: normal;
                }
            """)


class ChatPage(QWidget):
    """
    Main chat interface with sidebar and conversation area.
    
    Layout:
    - Left sidebar: Online users list with unread indicators
    - Right side: 
      - Top bar with username and theme button
      - Typing indicator
      - Scrollable message area with bubbles
      - Bottom input area for composing messages
    
    Features:
    - Real-time message display with sender/recipient styling
    - Message history per conversation (auto-pruned after 1 hour)
    - Unread message counters
    - Typing indicators with auto-timeout
    - Theme switching (cycles through 3 themes)
    
    Attributes:
        client: ChatClient backend instance
        theme: Current theme name (default, dark, or light)
        current_chat_user: Username of currently open conversation
        typing_timers: Dict of QTimer objects for typing indicator timeouts
        unread_messages: Dict mapping usernames to unread counts
        chat_history: Dict mapping usernames to message tuples (sender, message, timestamp)
    """

    def __init__(self, client: ChatClient):
        """
        Initialize the chat page.
        
        Args:
            client: Connected ChatClient instance
        """
        super().__init__()
        self.client = client
        self.theme = "default"
        self.current_chat_user = None  # Currently selected conversation
        self.typing_timers: Dict[str, QTimer] = {}  # Username -> timer
        self.unread_messages: Dict[str, int] = {}  # Username -> count
        self.chat_history: Dict[str, list] = {}  # Username -> [(sender, msg, time)]
        self.messages_scroll = None  # Scrollable message area
        self.messages_container = None  # Container widget for messages
        self.messages_layout = None  # Layout holding message bubbles

        self.init_ui()
        self.apply_theme()

    def init_ui(self):
        """
        Create and layout all chat page widgets.
        
        Creates a two-column layout:
        - Left: Fixed-width sidebar with user list
        - Right: Flexible conversation area with messages and input
        """
        # Main horizontal layout
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setLayout(main_layout)

        # ========== LEFT SIDEBAR ==========
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)  # Fixed width for sidebar
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        sidebar_layout.setSpacing(10)
        sidebar.setLayout(sidebar_layout)

        # Sidebar header
        sidebar_header = QLabel("Online Users")
        sidebar_header.setObjectName("sidebarHeader")
        sidebar_layout.addWidget(sidebar_header)

        # User list widget
        self.user_list = QListWidget()
        self.user_list.setObjectName("userList")
        self.user_list.itemDoubleClicked.connect(self.open_conversation)
        sidebar_layout.addWidget(self.user_list)

        main_layout.addWidget(sidebar)

        # ========== RIGHT SIDE (Conversation Area) ==========
        right_side = QFrame()
        right_side.setObjectName("conversationArea")
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_side.setLayout(right_layout)

        # --- Top Bar ---
        top_bar = QFrame()
        top_bar.setObjectName("topBar")
        top_bar.setFixedHeight(60)
        top_bar_layout = QHBoxLayout()
        top_bar_layout.setContentsMargins(20, 10, 20, 10)
        top_bar.setLayout(top_bar_layout)

        # Current chat user label
        self.chat_user_label = QLabel("Select a user to start chatting")
        self.chat_user_label.setObjectName("chatUserLabel")
        top_bar_layout.addWidget(self.chat_user_label)

        top_bar_layout.addStretch()

        # Theme button
        self.theme_btn = QPushButton("Theme")
        self.theme_btn.setObjectName("themeButton")
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.clicked.connect(self.cycle_theme)
        top_bar_layout.addWidget(self.theme_btn)

        right_layout.addWidget(top_bar)
        right_layout.addSpacing(10)

        # --- Typing Indicator ---
        self.typing_label = QLabel("")
        self.typing_label.setObjectName("typingIndicator")
        self.typing_label.setFixedHeight(25)
        self.typing_label.setContentsMargins(20, 0, 20, 5)
        right_layout.addWidget(self.typing_label)

        # --- Messages Area (Scrollable) ---
        self.messages_scroll = QScrollArea()
        self.messages_scroll.setObjectName("messagesScroll")
        self.messages_scroll.setWidgetResizable(True)
        self.messages_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # Container for message bubbles
        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout()
        self.messages_layout.setContentsMargins(10, 10, 10, 10)
        self.messages_layout.setSpacing(6)
        self.messages_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.messages_container.setLayout(self.messages_layout)

        # Add expanding spacer at bottom to push messages up
        self.bottom_spacer = QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        self.messages_layout.addItem(self.bottom_spacer)

        self.messages_scroll.setWidget(self.messages_container)
        right_layout.addWidget(self.messages_scroll)

        # --- Bottom Input Area ---
        input_container = QFrame()
        input_container.setObjectName("inputContainer")
        input_container.setFixedHeight(70)
        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(20, 10, 20, 10)
        input_container.setLayout(input_layout)

        # Message input field
        self.message_input = QLineEdit()
        self.message_input.setObjectName("messageInput")
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.returnPressed.connect(self.send_message)
        self.message_input.textChanged.connect(self.on_typing)

        # Send button
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("sendButton")
        self.send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_btn.clicked.connect(self.send_message)

        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_btn)

        right_layout.addWidget(input_container)

        main_layout.addWidget(right_side)

    def prune_old_messages(self, username: str):
        """
        Remove messages older than 1 hour from chat history.
        
        This prevents memory buildup from long conversations while maintaining
        recent context.
        
        Args:
            username: User whose message history to prune
        """
        if username not in self.chat_history:
            return
        
        # Calculate cutoff time (1 hour ago)
        cutoff = datetime.now() - timedelta(hours=1)
        
        # Filter out old messages
        self.chat_history[username] = [
            (s, m, t) for (s, m, t) in self.chat_history[username]
            if t > cutoff
        ]

    def cycle_theme(self):
        """
        Cycle to next theme: default -> dark -> light -> default.
        
        Immediately applies the new theme to all visible widgets.
        """
        themes = ["default", "dark", "light"]
        current_index = themes.index(self.theme)
        self.theme = themes[(current_index + 1) % len(themes)]
        self.apply_theme()

    def apply_theme(self):
        """
        Apply current theme stylesheet to all chat page widgets.
        
        Each theme defines colors for:
        - Sidebar and user list
        - Top bar and headers
        - Message area background
        - Input area
        - Buttons and text
        """
        if self.theme == "dark":
            # dark mode colors
            self.setStyleSheet("""
                QFrame#sidebar { background-color: #2f3136; border-right: 1px solid #202225; }
                QLabel#sidebarHeader { font-size: 12px; font-weight: bold; color: #96989d; padding: 5px; text-transform: uppercase; }
                QListWidget#userList { background-color: #2f3136; border: none; color: #dcddde; font-size: 14px; }
                QScrollArea#messagesScroll { background-color: #36393f; border: none; padding-top: 10px; }
                QFrame#conversationArea { background-color: #36393f; }
                QFrame#topBar { background-color: #2b2d2f; border-bottom: 1px solid #202225; }
                QLabel#chatUserLabel { font-size: 16px; font-weight: bold; color: #ffffff; }
                QPushButton#themeButton { background-color: #5865f2; color: white; border: none; border-radius: 6px; padding: 8px 16px; }
                QLabel#typingIndicator { color: #b9bbbe; font-size: 12px; font-style: italic; padding-left: 16px; }
                QFrame#inputContainer { background-color: #2b2d2f; border-top: 1px solid #202225; }
                QLineEdit#messageInput { background-color: #40444b; border: 1px solid #202225; border-radius: 8px; padding: 12px; color: #dcddde; }
                QPushButton#sendButton { background-color: #5865f2; color: white; border: none; border-radius: 8px; padding: 12px 24px; font-weight: bold; }
            """)
        elif self.theme == "light":
            # light mode colors
            self.setStyleSheet("""
                QFrame#sidebar { background-color: #f2f3f5; border-right: 1px solid #e3e5e8; }
                QLabel#sidebarHeader { font-size: 12px; font-weight: bold; color: #5c5e66; padding: 5px; text-transform: uppercase; }
                QListWidget#userList { background-color: #f2f3f5; border: none; color: #2e3338; font-size: 14px; }
                QScrollArea#messagesScroll { background-color: #ffffff; border: none; padding-top: 10px; }
                QFrame#conversationArea { background-color: #ffffff; }
                QFrame#topBar { background-color: #ffffff; border-bottom: 1px solid #e3e5e8; }
                QLabel#chatUserLabel { font-size: 16px; font-weight: bold; color: #2e3338; }
                QPushButton#themeButton { background-color: #5865f2; color: white; border: none; border-radius: 6px; padding: 8px 16px; }
                QLabel#typingIndicator { color: #5c5e66; font-size: 12px; font-style: italic; padding-left: 16px; }
                QFrame#inputContainer { background-color: #f2f3f5; border-top: 1px solid #e3e5e8; }
                QLineEdit#messageInput { background-color: #ffffff; border: 1px solid #d4d7dc; border-radius: 8px; padding: 12px; color: #2e3338; }
                QPushButton#sendButton { background-color: #5865f2; color: white; border: none; border-radius: 8px; padding: 12px 24px; font-weight: bold; }
            """)
        else:  # default (green/gold theme)
            self.setStyleSheet("""
                QFrame#sidebar { background-color: #2d5016; border-right: 2px solid #d4af37; }
                QLabel#sidebarHeader { font-size: 12px; font-weight: bold; color: #d4af37; padding: 5px; text-transform: uppercase; }
                QListWidget#userList { background-color: #2d5016; border: none; color: #f0f8f0; font-size: 14px; }
                QScrollArea#messagesScroll { background-color: #eef5ea; border: none; padding-top: 10px; }
                QFrame#conversationArea { background-color: #eef5ea; }
                QFrame#topBar { background-color: #2d5016; border-bottom: 2px solid #d4af37; }
                QLabel#chatUserLabel { font-size: 16px; font-weight: bold; color: #d4af37; }
                QPushButton#themeButton { background-color: #d4af37; color: #2d5016; border: none; border-radius: 6px; padding: 8px 16px; font-weight: bold; }
                QLabel#typingIndicator { color: #4a7c2f; font-size: 12px; font-style: italic; padding-left: 16px; }
                QFrame#inputContainer { background-color: #f0f4f0; border-top: 1px solid #2d5016; }
                QLineEdit#messageInput { background-color: #ffffff; border: 2px solid #2d5016; border-radius: 8px; padding: 12px; color: #1a4d1a; }
                QPushButton#sendButton { background-color: #2d5016; color: #d4af37; border: none; border-radius: 8px; padding: 12px 24px; font-weight: bold; }
            """)

    def update_online_users(self, users: list):
        """
        Update the sidebar with current online users.
        
        Displays each user with:
        - Green dot indicator
        - Username
        - Unread message count (if any)
        
        Args:
            users: List of online usernames
        """
        self.user_list.clear()
        
        for user in users:
            # Don't show ourselves in the list
            if user != self.client.username:
                unread_count = self.unread_messages.get(user, 0)
                
                # Format: "🟢 username" or "🟢 username (count)"
                if unread_count > 0:
                    item = QListWidgetItem(f"🟢 {user} ({unread_count})")
                else:
                    item = QListWidgetItem(f"🟢 {user}")
                    
                self.user_list.addItem(item)

    def open_conversation(self, item: QListWidgetItem):
        """
        Open a conversation with the selected user.
        
        Actions:
        - Set as current chat user
        - Prune old messages (1+ hour old)
        - Update top bar with username
        - Clear and reload message history
        - Reset unread counter
        - Request public key if not available
        
        Args:
            item: QListWidgetItem that was double-clicked in user list
        """
        # Extract username from item text (remove emoji and unread count)
        username = item.text().replace("🟢 ", "").split(" (")[0]
        
        # Prune old messages before displaying
        self.prune_old_messages(username)

        # Set as current conversation
        self.current_chat_user = username
        self.chat_user_label.setText(f"💬 {username}")
        
        # Clear message view and reload history
        self.clear_messages_view()
        if username in self.chat_history:
            for sender, message, ts in self.chat_history[username]:
                self.add_message(sender, message, ts)
        
        # Clear unread count
        if username in self.unread_messages:
            self.unread_messages[username] = 0
            self.update_online_users(self.client.online_users)

        # Request public key if we don't have it yet
        if username not in self.client.user_public_keys:
            self.client._request_public_key(username)
        else:
            # Show encryption status
            self.add_system_message("🔒End-to-end encrypted conversation")

    def clear_messages_view(self):
        """
        Remove all message widgets from the messages layout.
        
        Preserves the bottom spacer which keeps messages aligned to top.
        """
        # Remove all items except the bottom spacer (last item)
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()

    def add_system_message(self, message: str):
        """
        Add a centered system notification message.
        
        System messages are styled differently from chat messages:
        - Centered alignment
        - Gray background
        - Smaller font
        - Used for status updates like "User connected"
        
        Args:
            message: System message text to display
        """
        label = QLabel(message)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setMaximumWidth(520)
        label.setStyleSheet("""
            background-color: rgba(128,128,128,0.15);
            padding: 6px 12px;
            border-radius: 12px;
            color: gray;
            font-size: 11px;
            background: none;
            border: none;
        """)
        
        # Insert before bottom spacer
        self.messages_layout.insertWidget(
            self.messages_layout.count() - 1, 
            label, 
            0, 
            Qt.AlignmentFlag.AlignHCenter
        )
        
        # Scroll to bottom after short delay (allows layout to update)
        QTimer.singleShot(50, self._scroll_to_bottom)

    def add_message(self, sender: str, message: str, timestamp: datetime):
        """
        Add a message bubble to the chat view.
        
        Creates a styled message bubble with:
        - Sender name (for incoming messages)
        - Message text
        - Timestamp
        - Different styling for sent vs received messages
        - Theme-appropriate colors
        
        Message bubbles are aligned right for sent messages and left for
        received messages, similar to modern messaging apps.
        
        Args:
            sender: Username of message sender
            message: Message text content
            timestamp: When the message was sent/received
        """
        # Prune old messages before adding new one
        self.prune_old_messages(self.current_chat_user)
        
        # Format timestamp
        time_str = timestamp.strftime("%H:%M")
        
        # Store in chat history
        if sender not in self.chat_history:
            self.chat_history[sender] = []
        self.chat_history.setdefault(self.current_chat_user, []).append(
            (sender, message, timestamp)
        )

        # Create bubble container
        bubble_widget = QWidget()
        bubble_layout = QVBoxLayout()
        bubble_layout.setContentsMargins(6, 6, 6, 6)
        bubble_layout.setSpacing(4)
        bubble_widget.setLayout(bubble_layout)
        bubble_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        # Create message label
        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        msg_label.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)

        # Create timestamp label
        time_label = QLabel(time_str)
        time_label.setAlignment(Qt.AlignmentFlag.AlignRight)

        # Style and position based on sender
        if sender == self.client.username:
            # Outgoing message (sent by us)
            if self.theme == "dark":
                bg = "#5865f2"; color = "white"; time_color = "rgba(255,255,255,0.6)"
            elif self.theme == "light":
                bg = "#5865f2"; color = "white"; time_color = "rgba(255,255,255,0.8)"
            else:
                bg = "#2d5016"; color = "#ffeb3b"; time_color = "#b8d99f"
            
            msg_label.setStyleSheet(f"""
                background-color: {bg}; 
                color: {color}; 
                padding: 10px; 
                border-radius: 14px;
                text-overflow: clip;
                white-space: normal;
            """)
            time_label.setStyleSheet(f"font-size:10px; color: {time_color};")
            
            # Add widgets aligned to right
            bubble_layout.addWidget(msg_label, 0, Qt.AlignmentFlag.AlignRight)
            bubble_layout.addWidget(time_label, 0, Qt.AlignmentFlag.AlignRight)
            self.messages_layout.insertWidget(
                self.messages_layout.count() - 1, 
                bubble_widget, 
                0, 
                Qt.AlignmentFlag.AlignRight
            )
        else:
            # Incoming message (received from other user)
            if self.theme == "dark":
                bg = "#40444b"; color = "#dcddde"; time_color = "#96989d"
            elif self.theme == "light":
                bg = "#e3e5e8"; color = "#2e3338"; time_color = "#5c5e66"
            else:
                bg = "#d4e8d4"; color = "#1a4d1a"; time_color = "#5a7a3c"
            
            # Add sender name label for incoming messages
            sender_label = QLabel(f"<b>{sender}</b>")
            sender_label.setStyleSheet(f"color: {color}; font-size:12px;")
            
            msg_label.setStyleSheet(f"""
                background-color: {bg}; 
                color: {color}; 
                padding: 10px; 
                border-radius: 14px;
                text-overflow: clip;
                white-space: normal;
            """)
            time_label.setStyleSheet(f"font-size:10px; color: {time_color};")
            
            # Add widgets aligned to left
            bubble_layout.addWidget(sender_label, 0, Qt.AlignmentFlag.AlignLeft)
            bubble_layout.addWidget(msg_label, 0, Qt.AlignmentFlag.AlignLeft)
            bubble_layout.addWidget(time_label, 0, Qt.AlignmentFlag.AlignLeft)
            self.messages_layout.insertWidget(
                self.messages_layout.count() - 1, 
                bubble_widget, 
                0, 
                Qt.AlignmentFlag.AlignLeft
            )

        # Set maximum width (75% of scroll area width)
        bubble_widget.setMaximumWidth(int(self.messages_scroll.width() * 0.75))
        bubble_widget.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)

        # Scroll to show new message
        QTimer.singleShot(50, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        """
        Scroll the message area to show the most recent message.
        
        Helper method called after adding messages to ensure they're visible.
        """
        scrollbar = self.messages_scroll.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def send_message(self):
        """
        Send the message in the input field to the current chat user.
        
        Process:
        1. Validate that a user is selected
        2. Get and validate message text
        3. Check if public key is available (request if not)
        4. Add message to UI immediately
        5. Send encrypted message via client backend
        6. Clear input field
        
        Shows appropriate warnings/notifications if prerequisites aren't met.
        """
        # Validate user is selected
        if not self.current_chat_user:
            QMessageBox.warning(self, "No User Selected", "Please select a user to chat with")
            return

        # Get message text
        message = self.message_input.text().strip()
        if not message:
            return

        # Check if we have recipient's public key
        if self.current_chat_user not in self.client.user_public_keys:
            # Show status message and request key
            self.add_system_message(f"⏳ Establishing secure connection with {self.current_chat_user}...")
            self.client._request_public_key(self.current_chat_user)
            
            # Queue message to send after key arrives
            self.client.pending_messages[self.current_chat_user] = message
            self.message_input.clear()
            return

        # Add to UI immediately (optimistic update)
        self.add_message(self.client.username, message, datetime.now())
        
        # Store in history
        ts = datetime.now()
        self.chat_history.setdefault(self.current_chat_user, []).append(
            (self.client.username, message, ts)
        )
        
        # Send through backend
        self.client.send_message(self.current_chat_user, message)

        # Clear input field
        self.message_input.clear()

    def on_typing(self):
        """
        Called when user types in the message input field.
        
        Sends a typing indicator to the current chat user if there's
        text in the input field.
        """
        if self.current_chat_user and self.message_input.text():
            self.client.send_typing_indicator(self.current_chat_user)

    def show_typing_indicator(self, sender: str):
        """
        Display typing indicator for a user.
        
        Shows "{username} is typing..." text that automatically clears
        after 3 seconds. If user is already showing as typing, restarts
        the timer.
        
        Args:
            sender: Username of the user who is typing
        """
        # Only show if it's the current conversation
        if sender == self.current_chat_user:
            self.typing_label.setText(f"{sender} is typing...")

            # Clear existing timer if any
            if sender in self.typing_timers:
                self.typing_timers[sender].stop()

            # Create new timer to clear indicator after 3 seconds
            timer = QTimer()
            timer.timeout.connect(lambda: self.clear_typing_indicator(sender))
            timer.setSingleShot(True)
            timer.start(3000)  # 3 second timeout
            self.typing_timers[sender] = timer

    def clear_typing_indicator(self, sender: str):
        """
        Clear the typing indicator for a specific user.
        
        Args:
            sender: Username whose typing indicator should be cleared
        """
        if sender == self.current_chat_user:
            self.typing_label.setText("")

    def handle_incoming_message(self, sender: str, message: str, timestamp: datetime):
        """
        Handle a message received from the backend.
        
        If the message is from the currently open conversation, displays it
        immediately. Otherwise, increments unread counter and shows a brief
        notification in the top bar.
        
        Args:
            sender: Username who sent the message
            message: Decrypted message text
            timestamp: When message was received
        """
        # Store in history
        ts = timestamp
        self.chat_history.setdefault(sender, []).append(
            (sender, message, ts)
        )
        
        if sender == self.current_chat_user:
            # Currently viewing this conversation - show message
            self.add_message(sender, message, timestamp)
            
            # Clear typing indicator when message arrives
            self.clear_typing_indicator(sender)
        else:
            # Not currently viewing - increment unread counter
            if sender not in self.unread_messages:
                self.unread_messages[sender] = 0
            self.unread_messages[sender] += 1
            self.update_online_users(self.client.online_users)

            # Show brief notification in top bar
            current_display = f"💬 {self.current_chat_user}" if self.current_chat_user else "Select a user"
            self.chat_user_label.setText(f"{current_display} • New message from {sender}")
            
            # Clear notification after 3 seconds
            QTimer.singleShot(3000, lambda: self.chat_user_label.setText(current_display))

    def handle_user_connected(self, username: str):
        """
        Handle notification that a user connected or we received their public key.
        
        If there are pending messages for this user, sends them now that we
        have their public key.
        
        Args:
            username: Username who connected/became available
        """
        # Only show message if currently chatting with this user
        if self.current_chat_user == username:
            # Send any pending messages
            if username in self.client.pending_messages:
                pending_msg = self.client.pending_messages.pop(username)
                ts = datetime.now()
                
                # Add to history and display
                self.chat_history.setdefault(self.current_chat_user, []).append(
                    (self.client.username, pending_msg, ts)
                )
                self.add_message(self.client.username, pending_msg, ts)
                
                # Send via backend
                self.client.send_message(username, pending_msg)


class MainWindow(QWidget):
    """
    Main application window managing page transitions.
    
    Uses a QStackedWidget to switch between:
    1. LoginPage - Initial authentication
    2. ChatPage - Main messaging interface (created after successful login)
    
    Also manages the ChatClient instance and wires up callbacks to connect
    the backend to the GUI via thread-safe Qt signals.
    
    Attributes:
        client: ChatClient instance (created during login)
        signals: ChatSignals instance for thread-safe GUI updates
        stacked_widget: QStackedWidget for page navigation
        login_page: LoginPage instance
        chat_page: ChatPage instance (created after login)
    """

    def __init__(self):
        """Initialize the main window and signals."""
        super().__init__()
        self.setWindowTitle("Encrypted Messenger")
        self.setGeometry(100, 100, 1200, 700)

        self.client = None
        self.signals = ChatSignals()

        # Connect signals to GUI update slots
        self.signals.message_received.connect(self.handle_message)
        self.signals.system_message.connect(self.display_system_message)
        self.signals.user_connected.connect(self.on_user_connected)
        self.signals.user_disconnected.connect(self.on_user_disconnected)
        self.signals.connection_established.connect(self.on_connected)
        self.signals.error_occurred.connect(self.display_error)
        self.signals.online_users_updated.connect(self.update_online_users)
        self.signals.typing_indicator.connect(self.handle_typing_indicator)

        self.init_ui()

    def init_ui(self):
        """
        Initialize the stacked widget for page navigation.
        
        Starts with login page. Chat page is created after successful login.
        """
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

        # Stacked widget to switch between login and chat pages
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)

        # Create and add login page
        self.login_page = LoginPage()
        self.login_page.login_successful.connect(self.attempt_connection)
        self.stacked_widget.addWidget(self.login_page)

        # Chat page will be created after successful login
        self.chat_page = None

    def attempt_connection(self, username: str, password: str, server_ip: str):
        """
        Attempt to connect to server with provided credentials.
        
        Process:
        1. Create ChatClient instance with server IP
        2. Wire up all backend callbacks to emit Qt signals
        3. Attempt connection
        4. On success: Create chat page and switch to it
        5. On failure: Show error dialog
        
        Args:
            username: User's username
            password: User's password
            server_ip: Server IP address to connect to
        """
        # Create client with specified server
        self.client = ChatClient(username, server_ip=server_ip)

        # Wire up callbacks to emit signals for thread-safe GUI updates
        self.client.on_message_received = lambda s, m, t: self.signals.message_received.emit(s, m, t)
        self.client.on_system_message = lambda m: self.signals.system_message.emit(m)
        self.client.on_user_connected = lambda u: self.signals.user_connected.emit(u)
        self.client.on_user_disconnected = lambda u: self.signals.user_disconnected.emit(u)
        self.client.on_connection_established = lambda: self.signals.connection_established.emit()
        self.client.on_error = lambda e: self.signals.error_occurred.emit(e)
        self.client.on_online_users_updated = lambda u: self.signals.online_users_updated.emit(u)
        self.client.on_typing_indicator = lambda s: self.signals.typing_indicator.emit(s)

        # Try to connect
        if self.client.connect(password):
            # Connection successful - create and show chat page
            self.chat_page = ChatPage(self.client)
            self.stacked_widget.addWidget(self.chat_page)
            self.stacked_widget.setCurrentWidget(self.chat_page)
        else:
            # Connection failed - show error
            QMessageBox.critical(
                self, 
                "Connection Failed",
                "Failed to connect to server. Please check your credentials and server IP."
            )

    @pyqtSlot()
    def on_connected(self):
        """
        Called when connection to server is established.
        
        Shows a system message in the chat page.
        """
        if self.chat_page:
            self.chat_page.add_system_message(f"✅ Connected as {self.client.username}")

    @pyqtSlot(str, str, object)
    def handle_message(self, sender: str, message: str, timestamp):
        """
        Handle incoming message signal.
        
        Args:
            sender: Username who sent the message
            message: Decrypted message text
            timestamp: Message timestamp
        """
        if self.chat_page:
            self.chat_page.handle_incoming_message(sender, message, timestamp)

    @pyqtSlot(str)
    def display_system_message(self, message: str):
        """
        Display a system message (currently just prints to console).
        
        Args:
            message: System message text
        """
        print(f"[System]: {message}")

    @pyqtSlot(str)
    def display_error(self, error: str):
        """
        Display an error message in a dialog.
        
        Args:
            error: Error message text
        """
        QMessageBox.warning(self, "Error", error)

    @pyqtSlot(str)
    def on_user_connected(self, username: str):
        """
        Handle user connected notification.
        
        Args:
            username: Username who connected
        """
        if self.chat_page:
            self.chat_page.handle_user_connected(username)

    @pyqtSlot(str)
    def on_user_disconnected(self, username: str):
        """
        Handle user disconnected notification.
        
        Args:
            username: Username who disconnected
        """
        if self.chat_page:
            self.chat_page.add_system_message(f"🔴 {username} disconnected")

    @pyqtSlot(list)
    def update_online_users(self, users: list):
        """
        Update the online users list in the sidebar.
        
        Args:
            users: List of online usernames
        """
        if self.chat_page:
            self.chat_page.update_online_users(users)

    @pyqtSlot(str)
    def handle_typing_indicator(self, sender: str):
        """
        Show typing indicator for a user.
        
        Args:
            sender: Username who is typing
        """
        if self.chat_page:
            self.chat_page.show_typing_indicator(sender)

    def closeEvent(self, event):
        """
        Handle window close event.
        
        Ensures clean disconnection from server before exiting.
        
        Args:
            event: QCloseEvent
        """
        if self.client:
            self.client.disconnect()
        event.accept()


def main():
    """
    Main entry point for the GUI application.
    
    Creates the Qt application, main window, and starts the event loop.
    """
    print("Starting application...")
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for consistent cross-platform look

    print("Creating main window...")
    window = MainWindow()
    window.show()
    window.raise_()
    window.activateWindow()

    print("Application running. Close the window to exit.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()