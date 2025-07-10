import pytest
import os
from app import app, get_db_connection
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    # Setup test configuration
    app.config['TESTING'] = True
    app.config['DATABASE'] = 'file:test_db?mode=memory&cache=shared'
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    
    # Create fresh database schema
    with app.app_context():
        conn = get_db_connection()
        
        # Drop all tables if they exist
        conn.executescript("""
            PRAGMA foreign_keys = OFF;
            DROP TABLE IF EXISTS notes;
            DROP TABLE IF EXISTS participants;
            DROP TABLE IF EXISTS meetings;
            DROP TABLE IF EXISTS zoom_tokens;
            DROP TABLE IF EXISTS users;
            PRAGMA foreign_keys = ON;
        """)
        
        # Create tables in correct order
        conn.executescript("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
            
            CREATE TABLE zoom_tokens (
                user_id INTEGER PRIMARY KEY,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            CREATE TABLE meetings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                meeting_link TEXT,
                start_time DATETIME NOT NULL,
                end_time DATETIME NOT NULL,
                creator_id INTEGER NOT NULL,
                zoom_meeting_id TEXT,
                FOREIGN KEY (creator_id) REFERENCES users (id)
            );
            
            CREATE TABLE participants (
                meeting_id INTEGER,
                user_id INTEGER,
                PRIMARY KEY (meeting_id, user_id),
                FOREIGN KEY (meeting_id) REFERENCES meetings (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meeting_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (meeting_id) REFERENCES meetings (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(meeting_id, user_id)
            );
        """)
        
        # Add test user
        conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            ('test', 'test@test.com', generate_password_hash('123'))
        )
        conn.commit()
        conn.close()
    
    yield app.test_client()
    
    # Cleanup
    with app.app_context():
        conn = get_db_connection()
        conn.close()

def test_meeting_creation(client):
    # Login first (using session directly for testing)
    with client.session_transaction() as session:
        session['user_id'] = 1  # Assuming our test user has ID 1
    
    # Create meeting
    response = client.post('/meeting/create', data={
        'title': 'Test Meeting',
        'description': 'Test Desc',
        'start_time': '2023-01-01T10:00',
        'duration': '30'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Meeting created" in response.data
    
    # Verify DB
    with app.app_context():
        conn = get_db_connection()
        meeting = conn.execute(
            'SELECT * FROM meetings WHERE title = ?', 
            ('Test Meeting',)
        ).fetchone()
        assert meeting is not None
        conn.close()

def test_invalid_meeting_creation(client):
    with client.session_transaction() as session:
        session['user_id'] = 1
    
    # Missing title should fail
    response = client.post('/meeting/create', data={
        'description': 'Invalid Meeting',
        'start_time': '2023-01-01T10:00',
        'duration': '30'
    }, follow_redirects=True)
    
    assert b"Failed to create meeting" in response.data