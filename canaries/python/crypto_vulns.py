import hashlib
import random
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import ssl
import requests

# Crypto vulnerability #1: Weak hashing algorithm
def weak_password_hash(password):
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# Crypto vulnerability #2: SHA1 for password hashing
def sha1_password_hash(password):
    # Vulnerable: SHA1 is weak for password hashing
    return hashlib.sha1(password.encode()).hexdigest()

# Crypto vulnerability #3: Weak random number generation
def generate_session_token():
    # Vulnerable: random module is not cryptographically secure
    return str(random.randint(100000, 999999))

# Crypto vulnerability #4: Hardcoded encryption key
def encrypt_sensitive_data(data):
    # Vulnerable: Hardcoded key
    key = b'this_is_a_32_byte_key_for_aes256!!'
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data.encode()) + encryptor.finalize()

# Crypto vulnerability #5: ECB mode (insecure)
def insecure_aes_encryption(data, key):
    # Vulnerable: ECB mode reveals patterns
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Crypto vulnerability #6: Weak SSL/TLS configuration
def make_insecure_request():
    # Vulnerable: Disabling SSL verification
    response = requests.get('https://api.example.com/data', verify=False)
    return response.text

# Crypto vulnerability #7: Deprecated SSL context
def create_weak_ssl_context():
    # Vulnerable: Using deprecated/weak SSL protocols
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    return context

# Crypto vulnerability #8: Predictable IV
def encrypt_with_predictable_iv(data, key):
    # Vulnerable: Using predictable IV
    iv = b'1234567890123456'  # Fixed IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Crypto vulnerability #9: Insufficient key length
def generate_weak_key():
    # Vulnerable: 64-bit key is too short
    return os.urandom(8)  # Only 64 bits

# Example usage
if __name__ == '__main__':
    password = "user123"
    weak_hash = weak_password_hash(password)
    print(f"Weak hash: {weak_hash}")

    token = generate_session_token()
    print(f"Weak token: {token}")

    # Demonstrate weak encryption
    key = generate_weak_key()
    data = b"sensitive information"
    encrypted = insecure_aes_encryption(data, key)
    print(f"Insecurely encrypted: {encrypted}")