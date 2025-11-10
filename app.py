import sqlite3
import hashlib
import uuid
from flask import Flask, render_template, request, jsonify, session

import os # NEW: Import the os module for path resolution

# --- PATH RESOLUTION FIX ---
# Determine the absolute path of the directory containing this script.
# This ensures Flask finds 'templates' and 'ctf_secrets.db' regardless of
# the current working directory.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- FLASK SETUP ---
# Explicitly set the template folder path and root path
app = Flask(__name__, 
            template_folder=os.path.join(BASE_DIR, 'templates')
           )
# Hardcoded non-secret key, as secrets cannot be imported or referenced here.
app.secret_key = 'A_NON_SECRET_KEY_FOR_LAB_SESSIONS' 

DB_NAME = os.path.join(BASE_DIR, 'ctf_secrets.db') # NEW: Join BASE_DIR to the DB name


# --- FLASK SETUP ---
# app = Flask(__name__, template_folder='templates')
# Hardcoded non-secret key, as secrets cannot be imported or referenced here.
#app.secret_key = 'A_NON_SECRET_KEY_FOR_LAB_SESSIONS' 

#DB_NAME = 'ctf_secrets.db'

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
    """
    Hashes the user-submitted password for DB comparison.
    NOTE: The salt is hardcoded here because it MUST be known to correctly 
    hash the user's plaintext password to match the hash stored in the database.
    This value must match the SALT used in db_setup.py.
    """
    KNOWN_SALT = 'Fall2025' 
    
    # Using .format() for Python 3.4 compatibility
    # The process is: hash(SALT + password)
    return hashlib.sha256((password+KNOWN_SALT ).encode('utf-8')).hexdigest()

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
        # Template relies on relative path for API calls.
        # No configuration hints are passed.
    }
    # Using the single, simplified student_view template
    # return render_template('student_view.html', **template_data)
    return render_template('instructor_view.html', **template_data)

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
            # Fetch the encrypted message and the hash used as the decryption key
            secret_row = conn.execute('SELECT encrypted_message, encryption_key_hash FROM secrets WHERE id = 1').fetchone()
            conn.close()

            if secret_row:
                # The decryption key is the ADMIN_PASSWORD_HASH fetched from the DB secrets table
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
    print("!!! IMPORTANT: Ensure you run 'python db_setup.py' first !!!")
    print("!!! STARTING VULNERABLE HTTP SERVER on http://0.0.0.0:5000 !!!")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
