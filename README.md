This Python-based Secure Data Encryption System allows users to safely store and retrieve sensitive information using Fernet encryption from the cryptography library. The application provides a user-friendly interface built with Streamlit, featuring:

Key Features:
End-to-End Encryption: Data is encrypted before storage and decrypted only with the correct passkey.
Brute Force Protection: Blocks access after 3 failed decryption attempts, redirecting to a login page.
Session-Based Storage: Encrypted data persists securely during the app session.
SHA-256 Hashing: Passkeys are hashed for additional security.

How It Works:
Store Data: Users input text and a passkey → data is encrypted and stored.

Retrieve Data: Enter the encrypted text and passkey → system decrypts if credentials match.

Security: Failed attempts trigger a lockdown, requiring admin reauthentication.

Tech Stack: Python, Streamlit, Cryptography (Fernet), Hashlib (SHA-256).
