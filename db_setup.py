import sqlite3
import config  # Import configuration constants and functions

DB_NAME = 'ctf_secrets.db'

# --- Utility Functions ---

def xor_encrypt(data, key):
    """Simple XOR cipher for encryption/decryption."""
    encrypted_data = []
    # Use bytearray so indexing returns integer values across Python versions
    key_bytes = bytearray(key.encode('utf-8'))
    data_bytes = bytearray(data.encode('utf-8'))

    for i in range(len(data_bytes)):
        # XOR the data byte with a byte from the key (key wraps around)
        encrypted_byte = data_bytes[i] ^ key_bytes[i % len(key_bytes)]
        encrypted_data.append(format(encrypted_byte, '02x'))  # Store as two-digit hex string

    return "".join(encrypted_data)


def init_db():
    """Initializes the SQLite database with users and the encrypted secret."""
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # 1. Create USERS table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL
            );
        ''')

        # 2. Create SECRETS table (stores the single encrypted secret)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                encrypted_message TEXT NOT NULL,
                encryption_key_hash TEXT NOT NULL
                       
                
            );
        ''')
        #encryption_key_hash TEXT NOT NULL
        
        # 3. Insert Users
        print("Adding {} users to the database...".format(len(config.USERS)))
        for user in config.USERS:
            # Hash the user's plaintext password using the function from config.py
            hashed_password = config.hash_password(user['plaintext_password'])

            cursor.execute('''
                INSERT OR REPLACE INTO users (username, password_hash, is_admin)
                VALUES (?, ?, ?)
            ''', (
                user['username'],
                hashed_password,
                1 if user['is_admin'] else 0
            ))
            print("  - Added/Updated user: {}".format(user['username']))

        # 4. Encrypt and Insert Secret Message

        # The key for encryption is the HASH of the admin's password
        encryption_key = config.ADMIN_PASSWORD_HASH

        # The unique ID ensures the secret table is only populated once
        secret_id = 1

        encrypted_secret = xor_encrypt(config.SECRET_MESSAGE, encryption_key)
        #, encryption_key_hash) removed from table below
        cursor.execute('''
            INSERT OR REPLACE INTO secrets (id, encrypted_message, encryption_key_hash) 
            VALUES (?, ?, ?)
        ''', (
            secret_id,
            encrypted_secret,
            encryption_key
        ))

        print("\n--- Setup Complete ---")
        print("Database '{}' initialized successfully.".format(DB_NAME))
        print("Secret message encrypted using key hash: {}...".format(encryption_key[:10]))

        conn.commit()

    except sqlite3.Error as e:
        print("SQLite error during setup: {}".format(e))
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Ensure this script is only run directly for initialization
    init_db()
