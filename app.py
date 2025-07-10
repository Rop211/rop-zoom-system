import os
import sqlite3
import base64
from functools import wraps
from flask import Flask, render_template, request,redirect, url_for, flash, send_from_directory, session, Response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import make_response
from xhtml2pdf import pisa
from io import BytesIO

load_dotenv()
print("Loaded CLIENT_ID:", os.getenv("ZOOM_CLIENT_ID"))
print("Loaded CLIENT_SECRET:", os.getenv("ZOOM_CLIENT_SECRET"))

import uuid
import jwt
import time
import requests
import json

# Zoom OAuth Configuration
CLIENT_ID = os.getenv('ZOOM_CLIENT_ID')
CLIENT_SECRET = os.getenv('ZOOM_CLIENT_SECRET')

REDIRECT_URI = ('http://127.0.0.1:5001/zoom/callback')

# Initialize Flask app

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'your-secret-key-123'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.execute('PRAGMA foreign_keys = ON;')
    conn.row_factory = sqlite3.Row
    return conn

def is_zoom_connected(user_id):
    conn = get_db_connection()
    result = conn.execute('SELECT access_token, expires_at FROM zoom_tokens WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()

    if result and result['access_token'] and int(result['expires_at']) > int(time.time()):
        return True
    return False


def init_db():
    try:
        with app.app_context():
            if not os.path.exists('schema.sql'):
                raise FileNotFoundError("schema.sql file not found")
            
            conn = get_db_connection()
            with open('schema.sql', 'r') as f:
                conn.executescript(f.read())
            conn.commit()
            print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization failed: {str(e)}")
        raise
    finally:
        if 'conn' in locals():
            conn.close()

def get_zoom_access_token():
    user_id = session.get('user_id')
    if not user_id:
        return None

    try:
        conn = get_db_connection()
        token_data = conn.execute('SELECT * FROM zoom_tokens WHERE user_id = ?', (user_id,)).fetchone()

        if token_data:
            if token_data['expires_at'] > int(time.time()):
                return token_data['access_token']  # Token still valid

            # Refresh token
            token_url = "https://zoom.us/oauth/token"
            auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            headers = {"Authorization": f"Basic {auth_header}"}
            params = {
                "grant_type": "refresh_token",
                "refresh_token": token_data['refresh_token']
            }

            response = requests.post(token_url, headers=headers, params=params)
            response.raise_for_status()
            new_data = response.json()

            # Save new tokens
            conn.execute('''
                UPDATE zoom_tokens 
                SET access_token = ?, refresh_token = ?, expires_at = ? 
                WHERE user_id = ?
            ''', (
                new_data['access_token'],
                new_data.get('refresh_token', token_data['refresh_token']),
                int(time.time()) + new_data['expires_in'] - 300,
                user_id
            ))
            conn.commit()

            return new_data['access_token']

        return None

    except Exception as e:
        print(f"Zoom token error: {e}")
        return None

    finally:
        if 'conn' in locals():
            conn.close()

def create_zoom_meeting(topic, start_time, duration_minutes, access_token):
    """Create a Zoom meeting using the provided OAuth access token."""
    headers = {
        'Authorization': f"Bearer {access_token}",
        'Content-Type': 'application/json'
    }

    data = {
        "topic": topic,
        "type": 2,  # Scheduled meeting
        "start_time": start_time,
        "duration": duration_minutes,
        "timezone": "UTC",
        "settings": {
            "join_before_host": True,
            "approval_type": 0,
            "waiting_room": False,
            "participant_video": True,
            "mute_upon_entry": False,
            "auto_recording": "none",
            "alternative_hosts": ""
        }
    }

    try:
        response = requests.post(
            "https://api.zoom.us/v2/users/me/meetings",
            headers=headers,
            json=data
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        error_msg = f"Zoom API error: {e.response.status_code}"
        if e.response.text:
            error_msg += f" - {e.response.text}"
        raise Exception(error_msg)
    except Exception as e:
        raise Exception(f"Failed to create Zoom meeting: {str(e)}")


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/meeting/create', methods=['GET', 'POST'])
@login_required
def create_meeting():
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form['title']
            description = request.form['description']
            start_time = request.form['start_time']
            duration = int(request.form.get('duration', 60))
            creator_id = session['user_id']

            # Convert to Zoom format
            start_datetime = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
            start_iso = start_datetime.isoformat() + 'Z'

            # ✅ Get Zoom token from DB
            conn = get_db_connection()
            token_row = conn.execute('SELECT * FROM zoom_tokens WHERE user_id = ?', (creator_id,)).fetchone()

            if not token_row or token_row['expires_at'] < int(time.time()):
                flash("Zoom token missing or expired. Please reconnect Zoom.", "danger")
                conn.close()
                return redirect(url_for('connect_zoom'))

            # ✅ Call Zoom with access token
            zoom_meeting = create_zoom_meeting(title, start_iso, duration, token_row['access_token'])

            # ✅ Save meeting to DB
            conn.execute('''
                INSERT INTO meetings (title, description, meeting_link, start_time, end_time, creator_id, zoom_meeting_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                title,
                description,
                zoom_meeting['join_url'],
                start_datetime,
                start_datetime + timedelta(minutes=duration),
                creator_id,
                zoom_meeting['id']
            ))
            conn.commit()
            conn.close()

            flash('Meeting created with Zoom link!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f'Meeting creation failed: {str(e)}', 'danger')
            return redirect(url_for('create_meeting'))

    return render_template('create_meeting.html')
 
from datetime import datetime

@app.route('/meeting/<int:meeting_id>/collaborate')
@login_required
def meeting_collaboration(meeting_id):
    user_id = session['user_id']
    try:
        conn = get_db_connection()
        
        # Fetch meeting
        meeting = conn.execute('''
            SELECT m.*, u.username as creator_name 
            FROM meetings m
            JOIN users u ON m.creator_id = u.id
            WHERE m.id = ?
        ''', (meeting_id,)).fetchone()

        if not meeting:
            flash('Meeting not found', 'danger')
            return redirect(url_for('dashboard'))

        # Enforce: Allow notes access only after meeting starts
        start_time = datetime.strptime(meeting['start_time'], "%Y-%m-%d %H:%M:%S")
        now = datetime.utcnow()
        if now < start_time:
            flash("You can access notes after the meeting starts.", "warning")
            return redirect(url_for('dashboard'))

        # Mark user as participant if not already
        conn.execute('''
            INSERT OR IGNORE INTO participants (meeting_id, user_id)
            VALUES (?, ?)
        ''', (meeting_id, user_id))
        conn.commit()

        # Fetch shared notes
        notes = conn.execute('''
            SELECT n.*, u.username 
            FROM notes n
            JOIN users u ON n.user_id = u.id
            WHERE n.meeting_id = ?
            ORDER BY n.created_at DESC
        ''', (meeting_id,)).fetchall()

        return render_template(
            'meeting_collaboration.html',
            meeting=meeting,
            notes=notes,
            zoom_meeting_id=meeting['zoom_meeting_id']
        )

    except Exception as e:
        flash(f"Error loading meeting: {str(e)}", "danger")
        return redirect(url_for('dashboard'))
    finally:
        conn.close()


@app.route('/api/meeting/<int:meeting_id>/notes', methods=['POST'])
@login_required
def save_meeting_notes(meeting_id):
    """Save meeting notes via API"""
    user_id = session['user_id']
    data = request.get_json()
    
    if not data or 'content' not in data:
        return jsonify({'error': 'Invalid request'}), 400
    
    try:
        conn = get_db_connection()
        
        # Save or update notes
        conn.execute('''
            INSERT INTO notes (meeting_id, user_id, content)
            VALUES (?, ?, ?)
            ON CONFLICT(meeting_id, user_id) 
            DO UPDATE SET content = excluded.content, created_at = CURRENT_TIMESTAMP
        ''', (meeting_id, user_id, data['content']))
        conn.commit()
        
        # Get updated note with username
        note = conn.execute('''
            SELECT n.*, u.username 
            FROM notes n
            JOIN users u ON n.user_id = u.id
            WHERE n.meeting_id = ? AND n.user_id = ?
        ''', (meeting_id, user_id)).fetchone()
        
        return jsonify({
            'success': True,
            'note': dict(note),
            'message': 'Notes saved successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/meeting/<int:meeting_id>/notes/export')
@login_required
def export_meeting_notes(meeting_id):
    """Export all meeting notes as a single file"""
    try:
        conn = get_db_connection()
        
        # Get meeting details
        meeting = conn.execute('SELECT title FROM meetings WHERE id = ?', (meeting_id,)).fetchone()
        if not meeting:
            flash('Meeting not found', 'danger')
            return redirect(url_for('dashboard'))

        # Get all notes
        notes = conn.execute('''
            SELECT n.content, u.username, n.created_at
            FROM notes n
            JOIN users u ON n.user_id = u.id
            WHERE n.meeting_id = ?
            ORDER BY n.created_at
        ''', (meeting_id,)).fetchall()

        # Generate export content
        export_content = f"Meeting Notes: {meeting['title']}\n\n"
        export_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
        export_content += "="*50 + "\n\n"
        
        for note in notes:
            export_content += f"User: {note['username']}\n"
            export_content += f"Date: {note['created_at']}\n"
            export_content += "-"*30 + "\n"
            export_content += note['content'] + "\n\n"
            export_content += "="*50 + "\n\n"

        # Create downloadable response
        filename = f"meeting_notes_{meeting_id}_{datetime.now().strftime('%Y%m%d')}.txt"
        return Response(
            export_content,
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )

    except Exception as e:
        flash(f'Export failed: {str(e)}', 'danger')
        return redirect(url_for('meeting_collaboration', meeting_id=meeting_id))
    finally:
        if 'conn' in locals():
            conn.close()

from datetime import datetime

@app.route('/all_meetings')
@login_required
def all_meetings():
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        # Get meetings created by others or where the user is a participant
        meetings = conn.execute('''
            SELECT DISTINCT m.*, u.username as creator_name
            FROM meetings m
            JOIN users u ON m.creator_id = u.id
            LEFT JOIN participants p ON m.id = p.meeting_id
            WHERE m.creator_id != ? OR p.user_id = ?
            ORDER BY m.start_time DESC
        ''', (user_id, user_id)).fetchall()

        # Compute Upcoming/Past status
        now = datetime.utcnow()
        for m in meetings:
            start = datetime.strptime(m['start_time'], "%Y-%m-%d %H:%M:%S")
            m['status'] = "Upcoming" if start > now else "Past"

        return render_template('all_meetings.html', meetings=meetings)

    except Exception as e:
        flash(f"Failed to load meetings: {e}", "danger")
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route('/zoom/callback')
@login_required
def zoom_callback():
    code = request.args.get('code')
    if not code:
        flash('Authorization failed: No code received', 'danger')
        return redirect(url_for('dashboard'))

    token_url = "https://zoom.us/oauth/token"
    auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI
    }

    try:
        response = requests.post(token_url, headers=headers, data=payload)
        response.raise_for_status()
        token_data = response.json()

        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = session.get('user_id')

        # ✅ Check that user exists
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("Zoom callback failed: user does not exist in database", "danger")
            return redirect(url_for('dashboard'))

        # ✅ Insert or update Zoom token
        expires_at = int(time.time()) + token_data['expires_in'] - 300
        cursor.execute('''
            INSERT INTO zoom_tokens (user_id, access_token, refresh_token, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                access_token = excluded.access_token,
                refresh_token = excluded.refresh_token,
                expires_at = excluded.expires_at
        ''', (
            user_id,
            token_data['access_token'],
            token_data['refresh_token'],
            expires_at
        ))
        conn.commit()
        flash("Zoom connected successfully!", "success")

    except Exception as e:
        flash(f"Zoom callback failed: {e}", "danger")
    finally:
        if 'conn' in locals():
            conn.close()

    return redirect(url_for('dashboard'))


@app.route('/connect_zoom')
@login_required
def connect_zoom():
    zoom_auth_url = (
        f"https://zoom.us/oauth/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
    )
    return redirect(zoom_auth_url)


# ... (other routes like login, register, dashboard remain similar)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('all_meetings'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_pw))
            conn.commit()
            flash('Account created. You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db_connection()

    # Get meetings created or participated in
    meetings = conn.execute('''
        SELECT DISTINCT m.*, u.username as creator_name
        FROM meetings m
        JOIN users u ON m.creator_id = u.id
        LEFT JOIN participants p ON m.id = p.meeting_id
        WHERE m.creator_id = ? OR p.user_id = ?
        ORDER BY m.start_time DESC
    ''', (user_id, user_id)).fetchall()

    # Participants for each meeting
    participants_data = conn.execute('''
        SELECT p.meeting_id, u.username
        FROM participants p
        JOIN users u ON p.user_id = u.id
        WHERE p.meeting_id IN (
            SELECT id FROM meetings
            WHERE creator_id = ? OR id IN (
                SELECT meeting_id FROM participants WHERE user_id = ?
            )
        )
    ''', (user_id, user_id)).fetchall()

    participants = {}
    for row in participants_data:
        participants.setdefault(row['meeting_id'], []).append(row['username'])

    # Add meeting status
    current_time = datetime.utcnow()
    meetings = [dict(m) for m in meetings]  # Convert sqlite3.Row to dict
    for m in meetings:
        start_time = datetime.strptime(m['start_time'], "%Y-%m-%d %H:%M:%S")
        m['status'] = "Upcoming" if start_time > current_time else "Past"

    # Check Zoom connection
    zoom_connected = is_zoom_connected(user_id)

    conn.close()
    return render_template('dashboard.html', meetings=meetings,
                           participants=participants,
                           zoom_connected=zoom_connected)



@app.route('/')
def index():
    return render_template('login.html')  # Or any other default page like index.html

print("=== Available Routes ===")
for rule in app.url_map.iter_rules():
    print(f"{rule.endpoint:30s} {', '.join(rule.methods):25s} {rule}")

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
