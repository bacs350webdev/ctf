import hashlib

# --- GLOBAL CONFIGURATION ---
SALT = "Fall2026"
SECRET_MESSAGE = "Our greatest weakness lies in giving up. The most certain way to succeed is always to try just one more time. Thomas Edison"
SECRET_MESSAGE2 = "“Many of life's failures are people who did not realize how close they were to success when they gave up.”. Thomas Edison"
SECRET_MESSAGE3 = "“I have not failed. I've just found 10,000 ways that won't work.”. Thomas Edison"
SECRET_MESSAGE4 = "“Genius is one percent inspiration and ninety-nine percent perspiration.”. Thomas Edison"
SECRET_MESSAGE5 = "“The future belongs to those who believe in the beauty of their dreams.”. Eleanor Roosevelt"
SALT2 = "Fall2026"

ADMIN_PLAINTEXT_PASSWORD = "Bacs495_FA2026" # This is the password students will capture in the PCAP
NORMAL_PLAINTEXT_PASSWORD_1 = "BigSecret123"
NORMAL_PLAINTEXT_PASSWORD_2 = "secret456"

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
