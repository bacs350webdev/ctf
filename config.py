import hashlib

# --- GLOBAL CONFIGURATION ---
SALT = "Fall2025"
SECRET_MESSAGE = "Our greatest weakness lies in giving up. The most certain way to succeed is always to try just one more time."
ADMIN_PLAINTEXT_PASSWORD = "Bacs495_2025" # This is the password students will capture in the PCAP
NORMAL_PLAINTEXT_PASSWORD_1 = "userpass123"
NORMAL_PLAINTEXT_PASSWORD_2 = "secureuser99"

# --- UTILITY FUNCTION ---
def hash_password(password, salt=SALT):
    """Hashes the password with the global salt."""
    # Use SHA-256 for hashing
    salted_password = (password + salt).encode('utf-8')
    return hashlib.sha256(salted_password).hexdigest()

# --- DERIVED SECRETS (RUNTIME CONSTANTS) ---
ADMIN_PASSWORD_HASH = hash_password(ADMIN_PLAINTEXT_PASSWORD)

# USERS list for database initialization (db_setup.py uses this)
# Note: This config file should NOT be distributed to the students.
USERS = [
    {
        'username': 'ctf_admin',
        'plaintext_password': ADMIN_PLAINTEXT_PASSWORD,
        'is_admin': True
    },
    {
        'username': 'alice',
        'plaintext_password': NORMAL_PLAINTEXT_PASSWORD_1,
        'is_admin': False
    },
    {
        'username': 'bob',
        'plaintext_password': NORMAL_PLAINTEXT_PASSWORD_2,
        'is_admin': False
    }
]
