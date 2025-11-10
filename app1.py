import sqlite3
import hashlib
import uuid
from flask import Flask, render_template, request, jsonify, session
import config # Import configuration constants and functions
import time # Used for exponential backoff placeholder

# --- FLASK SETUP ---
app = Flask(__name__, template_folder='templates')
# Use a simple, non-secure key for session management
app.secret_key = config.SECRET_KEY 

DB_NAME = 'ctf_secrets.db'
API_BASE_URL = config.API_BASE_URL

# --- UTILITY FUNCTIONS ---

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def xor_decrypt(data_hex, key):
    """Simple XOR cipher for decryption."""
    decrypted_data = []
    # Ensure key is a string before encoding
    key_bytes = str(key).encode('utf-8')
    data_bytes = bytes.fromhex(data_hex) # Convert hex string back to bytes
    
    for i in range(len(data_bytes)):
        # XOR the data byte with a byte from the key (key wraps around)
        decrypted_byte = data_bytes[i] ^ key_bytes[i % len(key_bytes)]
        decrypted_data.append(chr(decrypted_byte))
        
    return "".join(decrypted_data)

def generate_unique_flag(session_id, decrypted_message, student_name):
    """Creates the unique, personalized flag."""
    # Simple hash of the session ID to create a unique challenge part
    unique_hash = hashlib.sha1(session_id.encode('utf-8')).hexdigest()[:8].upper()
    
    # Use the student's name (sanitized) to make the flag unique
    sanitized_name = student_name.replace(' ', '_').upper()
    
    # Structure: CTF{HASH_STUDENTNAME_MESSAGE_SNIPPET}
    # Using .format() for Python 3.4 compatibility
    return "CTF{{{0}_{1}_{2}}}".format(
        unique_hash, 
        sanitized_name, 
        decrypted_message[:15].replace(' ', '_')
    )

def hash_password_submit(password):
    """Hashes the user-submitted password for DB comparison."""
    # Using .format() for Python 3.4 compatibility
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    # Prepend the salt before hashing (standard practice, but kept simple here)
    # The complexity is handled in db_setup.py; here we match the hashing method.
    return hashlib.sha256((config.SALT + password).encode('utf-8')).hexdigest()

# --- FLASK ROUTES ---

@app.before_request
def make_session_permanent():
    """Ensure a session ID is always available for unique flags."""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())

@app.route('/', methods=['GET'])
def index():
    """Renders the Student View."""
    template_data = {
        'api_base_url': API_BASE_URL,
        'admin_username_hint': config.ADMIN_USER['username']
    }
    # Using the single, simplified student_view template
    return render_template('student_view.html', **template_data)

@app.route('/ctf_access', methods=['POST'])
def ctf_access():
    """Handles the insecure login and flag retrieval."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    student_name = data.get('student_name', 'UNKNOWN_STUDENT')
    session_id = session.get('session_id')
    
    if not username or not password or not student_name:
        return jsonify({'success': False, 'message': 'Missing username, password, or student name'}), 400

    # 1. Hash the password submitted by the student (client request is plain HTTP)
    submitted_password_hash = hash_password_submit(password)

    # 2. Look up the user in the database
    conn = get_db_connection()
    user = conn.execute('SELECT username, password_hash, is_admin FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if user and user['password_hash'] == submitted_password_hash:
        # Authentication successful
        
        if user['is_admin']:
            # ADMIN ACCESS GRANTED - RETRIEVE AND DECRYPT SECRET
            
            # Fetch the secret
            conn = get_db_connection()
            secret_row = conn.execute('SELECT encrypted_message, encryption_key_hash FROM secrets WHERE id = 1').fetchone()
            conn.close()

            if secret_row:
                # The decryption key is the ADMIN_PASSWORD_HASH itself
                decryption_key = secret_row['encryption_key_hash'] 
                encrypted_message = secret_row['encrypted_message']

                # Decrypt the message using the stored hash as the key
                decrypted_message = xor_decrypt(encrypted_message, decryption_key)
                
                # Generate the final unique flag using the student name
                final_flag = generate_unique_flag(session_id, decrypted_message, student_name)
                
                return jsonify({
                    'success': True,
                    'is_admin': True,
                    'message': 'FLAG CAPTURED! Successful admin access achieved via unencrypted HTTP.',
                    'flag': final_flag,
                    'secret_message': decrypted_message,
                    'student_name': student_name
                })
            
            return jsonify({'success': False, 'message': 'Admin login success, but secret not found in DB.'}), 500

        else:
            # Non-Admin user login success
            return jsonify({
                'success': True,
                'is_admin': False,
                'message': "Successfully logged in as {0}. You are a normal user; no classified flag was captured.".format(username),
                'student_name': student_name
            })

    else:
        # Authentication failed
        return jsonify({'success': False, 'message': 'Authentication failed. Check credentials.'}), 401

# --- RUN APPLICATION ---
if __name__ == '__main__':
    # NOTE: In a real server environment, the host should be restricted to '0.0.0.0' for external access.
    # The debug is set to False for production demonstration.
    print("!!! IMPORTANT: Ensure you run 'python db_setup.py' first !!!")
    print("!!! STARTING VULNERABLE HTTP SERVER on {0} !!!".format(API_BASE_URL))
    
    app.run(host='0.0.0.0', port=5000, debug=False)
