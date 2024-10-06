from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64
from werkzeug.utils import secure_filename
import csv

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads/'
ALLOWED_EXTENSIONS = {'csv'}

# MySQL Database connection details
db_config = {
    'host': 'localhost',        # Your MySQL host
    'user': 'root',             # Your MySQL username
    'password': 'vanillaice@1',  # Your MySQL password
    'database': 'hospital_db'   # The database name you want to connect to
}

# MySQL Database connection details
def create_connection():
    connection = None
    try:
        connection = mysql.connector.connect(**db_config)
    except Error as e:
        print(f"Error: {e}")
    return connection

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to generate a key for encryption
def generate_key(password: str):
    salt = os.urandom(16)  # Generates a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA256 for key derivation
        length=32,  # AES-256 requires a 32-byte key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key from the password
    return key, salt  # Return the key and salt

@app.route('/')
def welcome():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Collect form data
        hospital_name = request.form['hospital_name']
        hospital_id = request.form['hospital_id']
        department = request.form['department']
        department_id = request.form['department_id']
        admin_username = request.form['admin_username']
        admin_password = request.form['admin_password']
        confirm_password = request.form['confirm_password']
        email_address = request.form['email_address']
        verification_code = request.form['verification_code']

        # Input validation
        if not all([hospital_name, hospital_id, department, department_id, admin_username, admin_password, confirm_password, email_address, verification_code]):
            flash('All fields are required!')
            return redirect(url_for('signup'))

        if admin_password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')

        # Connect to the database
        connection = create_connection()
        if connection is None:
            flash('Database connection error.')
            return redirect(url_for('signup'))

        cursor = connection.cursor()
        query = """
            INSERT INTO users (hospital_name, hospital_id, department, department_id, admin_username, admin_password, email_address, verification_code)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        try:
            cursor.execute(query, (hospital_name, hospital_id, department, department_id, admin_username, hashed_password, email_address, verification_code))
            connection.commit()
            flash('Signup successful! Please upload the dataset.')
            return redirect(url_for('upload_file'))  # Redirect to the upload page after signup
        except Error as e:
            print(f"Error: {e}")
            flash('Error occurred while signing up.')
            return redirect(url_for('signup'))
        finally:
            cursor.close()
            connection.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        hospital_name = request.form['hospital_name']
        hospital_id = request.form['hospital_id']
        department = request.form['department']
        department_id = request.form['department_id']
        admin_password = request.form['admin_password']
        email_address = request.form['email_address']
        verification_code = request.form['verification_code']

        # Check if all fields are filled
        if not all([hospital_name, hospital_id, department, department_id, admin_password, email_address, verification_code]):
            flash('All fields are required!')
            return redirect(url_for('login'))

        # Connect to the database
        connection = create_connection()
        if connection is None:
            flash('Database connection error.')
            return redirect(url_for('login'))

        cursor = connection.cursor(dictionary=True)
        query = """
            SELECT * FROM users 
            WHERE hospital_name = %s 
            AND hospital_id = %s 
            AND email_address = %s
        """
        cursor.execute(query, (hospital_name, hospital_id, email_address))
        user = cursor.fetchone()

        if user and check_password_hash(user['admin_password'], admin_password):
            # Store session data to indicate the user is logged in
            session['logged_in'] = True
            session['user'] = {
                'hospital_name': hospital_name,
                'hospital_id': hospital_id,
                'email_address': email_address
            }
            flash('Login successful! Please upload the dataset.')
            return redirect(url_for('upload_file'))  # Redirect to upload page
        else:
            flash('Invalid credentials or email address.')
            return redirect(url_for('login'))

        cursor.close()
        connection.close()

    return render_template('login.html')

@app.route('/home')
def home():
    return render_template('home.html')

# Encryption function
def encrypt_data(data, key):
    backend = default_backend()
    iv = os.urandom(16)  # Initialization Vector for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Padding for the block cipher
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Return IV + ciphertext to allow decryption later

# File upload and encryption route
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Read CSV and encrypt the content
            key, salt = generate_key('encryptionpassword')  # Example password
            encrypted_data = encrypt_csv(filepath, key)

            # Save encrypted file (for demonstration purposes)
            encrypted_filename = 'encrypted_' + filename
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            with open(encrypted_filepath, 'wb') as enc_file:
                enc_file.write(encrypted_data)

            flash(f'File successfully uploaded and encrypted as {encrypted_filename}')
            return redirect(url_for('login'))
    return render_template('upload.html')

def encrypt_csv(filepath, key):
    with open(filepath, newline='') as csvfile:
        reader = csv.reader(csvfile)
        encrypted_rows = []
        for row in reader:
            encrypted_row = []
            for item in row:
                encrypted_item = encrypt_data(item.encode(), key)
                encrypted_row.append(base64.b64encode(encrypted_item).decode())  # Encode to base64 for readability
            encrypted_rows.append(encrypted_row)

    # Convert the encrypted rows back into a byte string for saving as a file
    encrypted_csv = '\n'.join([','.join(row) for row in encrypted_rows])
    return encrypted_csv.encode()

@app.route('/manual_entry', methods=['GET', 'POST'])
def manual_entry():
    if request.method == 'POST':
        # Handle manual data entry here
        data = request.form['data']  # Assuming you have a form field named 'data'
        flash('Manual entry submitted successfully.')
        return redirect(url_for('home'))  # Redirect to home after submission
    return render_template('manual_entry.html')


if __name__ == '__main__':
    app.run(debug=True)
