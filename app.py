from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
import sqlite3, os
from fundef import *

# we initiate the flask app
app = Flask(__name__)
app.secret_key = "herewego"

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("")
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
        )''')
    conn.commit()
    conn.close()

# for the first launch: init_db()
# path = "C:\\Users\\....\\PycharmProjects\\PassPy\\training\\"
# path = "./training"
# Normalize and resolve to an absolute path
# path = os.path.abspath(path) + "\\"


# Utility function to query the database
def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv


#@app.route('/')
#def home():
#    return render_template('home.html')

@app.route('/')
def home():
    # Check if cookies have been accepted
    if request.cookies.get('cookies_accepted') == 'true':
        return render_template('home.html', cookies_accepted=True)
    return render_template('home.html', cookies_accepted=False)

@app.route('/accept_cookies')
def accept_cookies():
    # Set a cookie indicating the user has accepted the policy
    response = make_response(redirect(url_for('home')))
    response.set_cookie('cookies_accepted', 'true', max_age=30*24*60*60)  # Expires in 30 days
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # conn = sqlite3.connect('users.db')
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['user'] = user[1]
            flash('Login successful!', 'success')
            # return render_template(url_for('dashboard'))
            return render_template('dashboard.html')
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            # conn = sqlite3.connect('users.db')
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            conn.close()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
    
    return render_template('register.html')

#----------------------------- dashbord or consult data -----------------------------
# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    user_passwords = query_db('SELECT * FROM passwords WHERE user_id = ?', (session['user_id'],))
    return render_template('dashboard.html', passwords=user_passwords)

# Delete Password Route
@app.route('/delete_password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    if 'user_id' in session:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        conn.commit()
        conn.close()
        flash("Password deleted successfully!", "success")
        return jsonify({"success": True})
    return jsonify({"error": "Unauthorized"}), 403

# Mock decryption function (replace with real decryption logic)
def decrypt_password(ciphertext):
    # Decrypt the password
    master_password = "my0;ma5teR_Pa5sW0rd"
    salt = b'secure_salt'
    key = generate_key(master_password, salt)
    decrypted_password = decrypt(ciphertext, key)
    return f"{decrypted_password}"

# Decrypt Password Route
@app.route('/decrypt_password/<int:password_id>', methods=['POST'])
def decrypt_password_route(password_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    # Fetch the password from the database
    password_entry = query_db('SELECT password_encr FROM passwords WHERE id = ?', (password_id,), one=True)
    if not password_entry:
        return jsonify({"error": "Password not found"}), 404

    ciphertext = password_entry['password_encr']
    plaintext = decrypt_password(ciphertext)

    return jsonify({"plaintext": plaintext})

#------------------------------------- Add Password Route ----------------------------
@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    account = request.form.get('account')
    username = request.form.get('username')
    password = request.form.get('password')

    if not account or not username or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for('dashboard'))

    # Insert the password entry into the database
    store_password(account, username, password, session["user_id"])

    flash("Password added successfully!", "success")
    return redirect(url_for('dashboard'))

#------------------------------------- Update password Route ----------------------------
@app.route('/update_password/<int:password_id>', methods=['POST'])
def update_password(password_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    # Parse JSON data from the request
    data = request.get_json()
    account = data.get("account")
    username = data.get("username")
    password = data.get("password")  # Assume encryption will be handled separately

    if not (account and username and password):
        return jsonify({"error": "Invalid input"}), 400

    # Update the database
    update_pass(session['user_id'], password_id, account, username, password)
    row = retrieve_apass(session['user_id'], password_id)
    # Return the updated data for the frontend
    updated_hash = "new_hash"  
    return jsonify({
        "success": True,
        "updated": {
            "account": row[1],
            "username": row[2],
            "password": row[3],
            "hash": row[4].decode('utf-8'),
        },
    })

# -----------------------------Password Generator Route------------------------
@app.route('/generate_password', methods=['GET'])
def generate_password_route():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    length = request.args.get('length', default=12, type=int)
    password = generate_secure_password(length) 
    return jsonify({"password": password})

#----------------------- Route for password strength analysis-----
@app.route('/analyze_password', methods=['POST'])
def analyze_password_route():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 403
    password = request.json.get('password', '')
    strength = test_password(password)
    
    return jsonify({"strength": strength, "score": 0})

#----------------------------------- Password tools page-------------------------
@app.route('/password_tools', methods=['GET'])
def password_tools():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('password_tools.html')


# --------------------- Route for attacks page---------------------------------
@app.route('/attacks', methods=['GET', 'POST'])
def attacks():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        attack_type = request.form['attack_type']
        hash_value = request.form['hash']
        response = {}

        hash_type = detect_hash_type(hash_value)
        if hash_type == "unknown":
            return jsonify({"error": "Unsupported hash type. Please provide a valid hash."}), 400

        if attack_type == "brute_force":
            max_length = int(request.form['max_length'])
            # plaintext, attempts, duration = brute_force_attack(hash_value, max_length)
            plaintext, attempts, duration = brute_force_attack(hash_value, hash_type, max_length)
            response = {
                "type": "Brute Force",
                "plaintext": plaintext,
                "attempts": attempts,
                "duration": duration,
            }

        elif attack_type == "dictionary":
            uploaded_file = request.files.get('dictionary_file')
            file_path = None
            if uploaded_file:
                file_path = f"static/uploads/{uploaded_file.filename}"
                uploaded_file.save(file_path)

            # plaintext, attempts, duration = dictionary_attack(hash_value, file_path)
            plaintext, attempts, duration = dictionary_attack(hash_value, hash_type, file_path)
            response = {
                "type": "Dictionary",
                "plaintext": plaintext,
                "attempts": attempts,
                "duration": duration,
            }

        return jsonify(response)

    return render_template('attacks.html')


#----------------------------- logout ----------------------------------------------------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

#----------------------about route-------------------------------
@app.route('/about')
def about():
    return render_template('about.html')


#------------------------cookies policy route -------------
@app.route('/cookies-policy')
def cookies_policy():
    return render_template('cookies_policy.html')


if __name__ == '__main__':
    # app.run(host="127.0.0.2", port=7000, debug=True)
    port = int(os.environ.get('PORT', 7000))
    app.run(host='0.0.0.0', port=port)
