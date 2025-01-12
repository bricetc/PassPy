#--------------------------Secured storage of password ------------------------------------

#--------------------------Encryption and decrytion
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os, base64
import sqlite3
import random, bcrypt, string, re
import string
import pandas as pd, numpy as np
import spacy, joblib
import itertools, time
import hashlib
from typing import Tuple


# path = "C:\\Users\\....\\PycharmProjects\\PassPy\\training\\"
path = "./training"
# Normalize and resolve to an absolute path 
path = os.path.abspath(path) + "\\"

DATABASE = path + "password_manager.db"

# Generate a key for AES encryption
def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# Encrypt plaintext
def encrypt(plaintext, key):
    # Add padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # AES encryption
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV and ciphertext
    return base64.b64encode(iv + ciphertext).decode()

# Decrypt ciphertext
def decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)

    # Extract IV and encrypted data
    iv = data[:16]
    encrypted_data = data[16:]

    # AES decryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode()

#-------------------------Hashing
import bcrypt

# Hash the master password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Verify the master password
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)


#------------------------------------ Database setup----------
def initialize_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL,
                      password TEXT NOT NULL)''')
    # Password table 
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      account TEXT NOT NULL,
                      username TEXT,
                      password_hash TEXT NOT NULL,
                      password_encr TEXT NOT NULL,
                      user_id INTEGER,
                      FOREIGN KEY(user_id) REFERENCES users(id) )''')
    conn.commit()
    conn.close()

# Store password securely
def store_password(account, username, password, user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Hash the password
    # password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    password_hash = hash_password(password)

    # Generate AES key and crypt the pass
    master_password = "my0;ma5teR_Pa5sW0rd"
    salt = b'secure_salt'  # Use a secure and consistent salt
    key = generate_key(master_password, salt)
    # Encrypt the password
    password_encr = encrypt(password, key)

    # Insert into database
    cursor.execute('INSERT INTO passwords (account, username, password_hash, password_encr, user_id) VALUES (?, ?, ?, ?, ?)',
                   (account, username, password_hash, password_encr, user_id))
    conn.commit()
    conn.close()

# Retrieve passwords
def retrieve_passwords(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Retrieve all passwords for the logged-in user
    # cursor.execute('SELECT id, account, username FROM passwords WHERE user_id = ?', (user_id,))
    cursor.execute('SELECT * FROM passwords WHERE user_id = ?', (user_id,))
    passwords = cursor.fetchall()
    conn.close()
    return passwords

# Retrieve specific password
def retrieve_apass(user_id, password_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Retrieve a specific password record for the user based on the account name
    cursor.execute('SELECT id, account, username, password_encr, password_hash FROM passwords WHERE user_id = ? AND id = ?', 
                   (user_id, password_id))
    password_record = cursor.fetchone()
    conn.close()

    if not password_record:
        return None

    # Decrypt the password
    master_password = "my0;ma5teR_Pa5sW0rd"
    salt = b'secure_salt'
    key = generate_key(master_password, salt)
    decrypted_password = decrypt(password_record[3], key)
    """
    return {
        "id": password_record[0],
        "account": password_record[1],
        "username": password_record[2],
        "password": decrypted_password
    }
    """
    return password_record

# Update an account password
def update_pass(user_id, password_id, account, new_username, new_password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Hash the new password
    password_hash = hash_password(new_password)

    # Encrypt the new password
    master_password = "my0;ma5teR_Pa5sW0rd"
    salt = b'secure_salt'
    key = generate_key(master_password, salt)
    password_encr = encrypt(new_password, key)

    # Update the password record in the database
    cursor.execute('''
        UPDATE passwords 
        SET username = ?, account = ?, password_hash = ?, password_encr = ? 
        WHERE user_id = ? AND id = ?''', 
        (new_username, account, password_hash, password_encr, user_id, password_id))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0  # Return True if a row was updated

# Delete password
def delete_pass(user_id, account):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Delete the password record for the given account and user
    cursor.execute('DELETE FROM passwords WHERE user_id = ? AND account = ?', (user_id, account))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0  # Return True if a row was deleted



#-----------------------------Password Generation------------------------------------------

import spacy, string, random
# Load English and French models
nlp_en = spacy.load("en_core_web_sm")
nlp_fr = spacy.load("fr_core_news_sm")

def resembles_common_word(password):
    # Check against both English and French models
    for nlp in [nlp_en, nlp_fr]:
        doc = nlp(password)
        for token in doc:
            if token.is_alpha and token.text.lower() in nlp.vocab:
                return True
    return False

def load_easy_patterns(file_path="easy_patterns.txt"):
    # Load patterns from the specified file
    with open(file_path, "r") as f:
        patterns = [line.strip() for line in f.readlines()]
    return patterns

def has_easy_patterns(password, patterns):
    # Check for sequential characters
    for i in range(len(password) - 2):
        if (ord(password[i+1]) == ord(password[i]) + 1) and (ord(password[i+2]) == ord(password[i]) + 2):
            return True
        if password[i] == password[i+1] == password[i+2]:  # Repeated characters
            return True
    # Check for patterns in the list
    for pattern in patterns:
        if pattern in password:
            return True
    return False

def generate_secure_password(length=12):
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    all_chars = string.ascii_letters + string.digits + string.punctuation
    easy_patterns = load_easy_patterns(path + "easy_patterns.txt")
    
    while True:
        password = ''.join(random.choice(all_chars) for _ in range(length))
        if not has_easy_patterns(password, easy_patterns) and not resembles_common_word(password):
            return password


#-----------------------------Password Strength analysis------------------------------------------

#---------------------- Feature extraction functions -----------------------------------
def count_uppercase(password):
    return sum(1 for c in password if c.isupper())

def count_lowercase(password):
    return sum(1 for c in password if c.islower())

def count_digits(password):
    return sum(1 for c in password if c.isdigit())

def count_special_chars(password):
    return sum(1 for c in password if not c.isalnum())

def has_sequential_chars(password):
    # Check for sequences of 3 or more characters
    sequential = False
    for i in range(len(password) - 2):
        substr = password[i:i+3]
        if substr.isalpha() or substr.isdigit():
            if ord(substr[1]) == ord(substr[0]) + 1 and ord(substr[2]) == ord(substr[1]) + 1:
                sequential = True
                break
    return int(sequential)

def calculate_entropy(password):
    # Calculate Shannon entropy
    entropy = 0
    length = len(password)
    if length == 0:
        return 0
    chars = set(password)
    for c in chars:
        p = password.count(c) / length
        entropy -= p * np.log2(p)
    return entropy
#----------------------------------------------------------------------------
# Load the saved model and label encoder
loaded_model = joblib.load(path + 'random_forest_model.pkl') # random_forest_model.pkl | mlp_model.pkl | knn_model.pkl
loaded_label_encoder = joblib.load(path + 'label_encoder.pkl')

def test_password(password):    
    # Extract features
    features = {
        'length': len(password),
        'uppercase': count_uppercase(password),
        'lowercase': count_lowercase(password),
        'digits': count_digits(password),
        'special_chars': count_special_chars(password),
        'sequential': has_sequential_chars(password),
        'entropy': calculate_entropy(password)
    }

    # Convert to a DataFrame with proper feature names
    input_features = pd.DataFrame([features])

    # Predict strength
    predicted_strength = loaded_model.predict(input_features)
    decoded_strength = loaded_label_encoder.inverse_transform(predicted_strength)

    return decoded_strength[0]


#------------------------Password Attacks functions-----------------------------
# Detect hash type based on length and pattern
def detect_hash_type(hashed_password: str) -> str:
    if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
        return "bcrypt"
    elif len(hashed_password) == 32:
        return "md5"
    elif len(hashed_password) == 40:
        return "sha1"
    elif len(hashed_password) == 64:
        return "sha256"
    else:
        return "unknown"

# Compare a hashed password with its plaintext version
def compare_hash(plaintext: str, hashed_password: str, hash_type: str) -> bool:
    if hash_type == "bcrypt":
        return bcrypt.checkpw(plaintext.encode(), hashed_password.encode())
    elif hash_type == "md5":
        return hashlib.md5(plaintext.encode()).hexdigest() == hashed_password
    elif hash_type == "sha1":
        return hashlib.sha1(plaintext.encode()).hexdigest() == hashed_password
    elif hash_type == "sha256":
        return hashlib.sha256(plaintext.encode()).hexdigest() == hashed_password
    else:
        return False

# Brute-force attack
def brute_force_attack(hashed_password: str, hash_type: str, max_length: int = 6):
    characters = string.ascii_letters + string.digits + string.punctuation
    start_time = time.time()
    attempts = 0

    for length in range(1, max_length + 1):
        for combination in itertools.product(characters, repeat=length):
            attempts += 1
            candidate = ''.join(combination)
            if compare_hash(candidate, hashed_password, hash_type):
                elapsed_time = time.time() - start_time
                return candidate, attempts, elapsed_time

    elapsed_time = time.time() - start_time
    return None, attempts, elapsed_time

# Dictionary attack
def dictionary_attack(hashed_password: str, hash_type: str, dictionary_file=None):
    start_time = time.time()
    attempts = 0

    # Default dictionary file if none provided
    if not dictionary_file:
        dictionary_file = path + "dictionary.txt"

    try:
        with open(dictionary_file, "r") as file:
            for line in file:
                attempts += 1
                candidate = line.strip()
                if compare_hash(candidate, hashed_password, hash_type):
                    elapsed_time = time.time() - start_time
                    return candidate, attempts, elapsed_time
    except FileNotFoundError:
        return None, attempts, time.time() - start_time

    elapsed_time = time.time() - start_time
    return None, attempts, elapsed_time
