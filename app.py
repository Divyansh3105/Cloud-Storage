from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_mysqldb import MySQL
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'DIV#3105pri'
app.config['MYSQL_DB'] = 'cloud_storage'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize MySQL
mysql = MySQL(app)

# App secret key and upload folder config
app.secret_key = '848deb68c624e79f033a3b30b1d734fa672868d91a6e7a3665663d72d42cb1bc'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 * 1024  # 1GB limit

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# AWS Configuration
app.config['AWS_ACCESS_KEY_ID'] = os.getenv('AWS_ACCESS_KEY_ID')
app.config['AWS_SECRET_ACCESS_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')
app.config['AWS_REGION'] = 'eu-north-1'
app.config['S3_BUCKET'] = os.getenv('S3_BUCKET')
app.config['S3_LOCAL_THRESHOLD'] = 10 * 1024 * 1024  # 10MB threshold

#S3 client initialization:
s3 = boto3.client(
    's3',
    aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
    region_name=app.config['AWS_REGION'],
    config=boto3.session.Config(
        signature_version='s3v4',
        s3={'addressing_style': 'virtual'}
    )
)

# Verify S3 connection
try:
    response = s3.list_buckets()
    logger.info("Available buckets: %s", [bucket['Name'] for bucket in response['Buckets']])
    if app.config['S3_BUCKET'] not in [bucket['Name'] for bucket in response['Buckets']]:
        logger.error("Bucket %s not found!", app.config['S3_BUCKET'])
except ClientError as e:
    logger.error("AWS Connection Error: %s", e)

# Database initialization
def init_db():
    try:
        with app.app_context():
            conn = mysql.connection
            cur = conn.cursor()

            # Create users table
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # Create files table with storage_type column
            cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                filepath VARCHAR(255) NOT NULL,
                filesize INT NOT NULL,
                is_important BOOLEAN DEFAULT FALSE,
                storage_type ENUM('local', 's3') DEFAULT 'local',
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                file_id INT NOT NULL,
                shared_with_user_id INT NOT NULL,
                shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files(id),
                FOREIGN KEY (shared_with_user_id) REFERENCES users(id)
            )
            """)


            conn.commit()
            cur.close()
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error("Error initializing database: %s", str(e))

# Initialize database
with app.app_context():
    init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
@login_required
def index():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT id, filename, filesize, uploaded_at, is_important, storage_type
            FROM files
            WHERE user_id = %s
            ORDER BY uploaded_at DESC
        """, (session['user_id'],))
        files = cur.fetchall()
        cur.close()
        return render_template('index.html', files=files)
    except Exception as e:
        logger.error("Error loading files: %s", str(e))
        flash('Error loading your files', 'danger')
        return render_template('index.html', files=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, username, password FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'danger')
        except Exception as e:
            logger.error("Login error: %s", str(e))
            flash('Login error. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        try:
            cur = mysql.connection.cursor()

            # Check if username or email already exists
            cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            if cur.fetchone():
                flash('Username or email already exists', 'danger')
                return redirect(url_for('register'))

            # Insert new user
            hashed_password = generate_password_hash(password)
            cur.execute("""
                INSERT INTO users (username, email, password)
                VALUES (%s, %s, %s)
            """, (username, email, hashed_password))

            mysql.connection.commit()
            cur.close()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            logger.error("Registration error: %s", str(e))
            flash('Registration failed. Please try again.', 'danger')

    return render_template('register.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))

    if file:
        try:
            filename = secure_filename(file.filename)
            file_content = file.read()
            filesize = len(file_content)
            file.seek(0)  # Reset file pointer

            if filesize < app.config['S3_LOCAL_THRESHOLD']:  # <10MB to S3
                try:
                    s3.upload_fileobj(
                        file,
                        app.config['S3_BUCKET'],
                        filename,
                        ExtraArgs={'ACL': 'private'}
                    )
                    filepath = f"s3://{app.config['S3_BUCKET']}/{filename}"
                    storage_type = 's3'
                    logger.info("File uploaded to S3: %s", filename)
                except Exception as s3_error:
                    logger.error("S3 Upload Error: %s", str(s3_error))
                    flash('Failed to upload to S3. Please check AWS credentials.', 'danger')
                    return redirect(url_for('index'))
            else:  # >=10MB locally
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                storage_type = 'local'
                logger.info("File saved locally: %s", filename)

            # Save to database
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO files (user_id, filename, filepath, filesize, storage_type)
                VALUES (%s, %s, %s, %s, %s)
            """, (session['user_id'], filename, filepath, filesize, storage_type))

            mysql.connection.commit()
            cur.close()
            flash('File uploaded successfully', 'success')

        except Exception as e:
            mysql.connection.rollback()
            logger.error("Upload error: %s", str(e))
            flash(f'Error uploading file: {str(e)}', 'danger')

    return redirect(url_for('index'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        logger.info("Attempting to download file: %s", filename)
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT id, filepath, storage_type
            FROM files
            WHERE user_id = %s AND filename = %s
        """, (session['user_id'], filename))
        file = cur.fetchone()
        cur.close()

        if not file:
            flash('File not found', 'danger')
            return redirect(url_for('index'))

        if file['storage_type'] == 's3':
            try:
                # Generate presigned URL with correct parameters
                url = s3.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': app.config['S3_BUCKET'],
                        'Key': filename,
                        'ResponseContentDisposition': f'attachment; filename="{filename}"'
                    },
                    ExpiresIn=3600,
                    HttpMethod='GET'
                )
                logger.info("Generated presigned URL: %s", url)
                return redirect(url)
            except ClientError as e:
                logger.error("S3 Download Error: %s", e)
                flash('Failed to generate download link. Please try again.', 'danger')
                return redirect(url_for('index'))
        else:
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                filename,
                as_attachment=True,
                download_name=filename
            )

    except Exception as e:
        logger.error("Download error: %s", str(e))
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    try:
        cur = mysql.connection.cursor()

        # First get the file info to verify ownership
        cur.execute("""
            SELECT id, filepath, storage_type
            FROM files
            WHERE user_id = %s AND filename = %s
        """, (session['user_id'], filename))
        file = cur.fetchone()

        if file:
            # First delete any sharing records for this file
            cur.execute("DELETE FROM shared_files WHERE file_id = %s", (file['id'],))

            if file['storage_type'] == 's3':
                # Delete from S3
                try:
                    s3.delete_object(
                        Bucket=app.config['S3_BUCKET'],
                        Key=filename
                    )
                    logger.info("Deleted file from S3: %s", filename)
                except ClientError as e:
                    logger.error("Error deleting from S3: %s", e)
                    raise
            else:
                # Delete from local filesystem
                if os.path.exists(file['filepath']):
                    os.remove(file['filepath'])
                    logger.info("Deleted local file: %s", file['filepath'])

            # Delete from database
            cur.execute("DELETE FROM files WHERE id = %s", (file['id'],))
            mysql.connection.commit()
            flash('File deleted successfully', 'success')
        else:
            flash('File not found', 'danger')

        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        logger.error("Delete error: %s", str(e))
        flash(f'Error deleting file: {str(e)}', 'danger')

    return redirect(url_for('index'))

@app.route('/mark_important/<filename>', methods=['POST'])
@login_required
def mark_important(filename):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE files
            SET is_important = NOT is_important
            WHERE user_id = %s AND filename = %s
        """, (session['user_id'], filename))
        mysql.connection.commit()
        cur.close()
        flash('File importance status updated', 'success')
    except Exception as e:
        mysql.connection.rollback()
        logger.error("Mark important error: %s", str(e))
        flash('Error updating file status', 'danger')
    return redirect(url_for('index'))

@app.route('/search')
@login_required
def search_files():
    query = request.args.get('q', '')
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT filename, filesize, uploaded_at, is_important, storage_type
            FROM files
            WHERE user_id = %s AND filename LIKE %s
            ORDER BY uploaded_at DESC
        """, (session['user_id'], f'%{query}%'))
        files = cur.fetchall()
        cur.close()
        return render_template('index.html', files=files, search_query=query)
    except Exception as e:
        logger.error("Search error: %s", str(e))
        flash('Error searching files', 'danger')
        return redirect(url_for('index'))

@app.route('/sort')
@login_required
def sort_files():
    sort_by = request.args.get('sort', 'date')
    order = request.args.get('order', 'desc')

    valid_sorts = ['date', 'name', 'size', 'important']
    valid_orders = ['asc', 'desc']

    if sort_by not in valid_sorts or order not in valid_orders:
        return redirect(url_for('index'))

    try:
        cur = mysql.connection.cursor()

        if sort_by == 'date':
            order_by = f"uploaded_at {order.upper()}"
        elif sort_by == 'name':
            order_by = f"filename {order.upper()}"
        elif sort_by == 'size':
            order_by = f"filesize {order.upper()}"
        elif sort_by == 'important':
            order_by = f"is_important DESC, uploaded_at DESC"

        cur.execute(f"""
            SELECT filename, filesize, uploaded_at, is_important, storage_type
            FROM files
            WHERE user_id = %s
            ORDER BY {order_by}
        """, (session['user_id'],))

        files = cur.fetchall()
        cur.close()
        return render_template('index.html', files=files, sort_by=sort_by, sort_order=order)
    except Exception as e:
        logger.error("Sort error: %s", str(e))
        flash('Error sorting files', 'danger')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
