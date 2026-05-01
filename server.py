import sqlite3
import os
import time
import bcrypt
import jwt
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from datetime import datetime, timezone, timedelta

# ═══════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, 'kwchecker.db')
SECRET    = os.environ.get('JWT_SECRET', 'kwchecker-jwt-secret-change-in-prod')
JWT_DAYS  = 7

app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ═══════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    is_archived INTEGER NOT NULL DEFAULT 0,
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS project_data (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    kw_input       TEXT NOT NULL DEFAULT '',
    text_input     TEXT NOT NULL DEFAULT '',
    old_text_input TEXT NOT NULL DEFAULT '',
    sort           TEXT NOT NULL DEFAULT 'import',
    theme          TEXT NOT NULL DEFAULT 'dark',
    compare_mode   INTEGER NOT NULL DEFAULT 0,
    meta_columns      TEXT NOT NULL DEFAULT '[]',
    keywords          TEXT NOT NULL DEFAULT '[]',
    bullet_texts      TEXT NOT NULL DEFAULT '[]',
    description_text  TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id, updated_at DESC);
"""

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    if SECRET == 'kwchecker-jwt-secret-change-in-prod':
        print('[WARNING] JWT_SECRET is using the default insecure value. Set the JWT_SECRET environment variable before deploying.')
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    # Migrations: add new columns to existing DBs without losing data
    for col, default in [
        ("bullet_texts",     "DEFAULT '[]'"),
        ("description_text", "DEFAULT ''"),
    ]:
        try:
            conn.execute(f"ALTER TABLE project_data ADD COLUMN {col} TEXT NOT NULL {default}")
            conn.commit()
            print(f'[DB] Migration: added {col} column')
        except Exception:
            pass  # Column already exists
    conn.close()
    print(f'[DB] Initialized: {DB_PATH}')

# ═══════════════════════════════════════════════════
# RATE LIMITING (in-memory, per IP)
# ═══════════════════════════════════════════════════
_rate_store = {}  # ip -> [timestamp, ...]
RATE_LIMIT   = 10
RATE_WINDOW  = 300  # 5 minutes

def check_rate_limit(ip):
    now = time.time()
    timestamps = [t for t in _rate_store.get(ip, []) if now - t < RATE_WINDOW]
    _rate_store[ip] = timestamps
    if len(timestamps) >= RATE_LIMIT:
        return False
    _rate_store[ip].append(now)
    return True

# ═══════════════════════════════════════════════════
# JWT HELPERS
# ═══════════════════════════════════════════════════
def make_token(user_id, email):
    payload = {
        'sub': str(user_id),  # PyJWT v2 requires string subject
        'email': email,
        'exp': datetime.now(timezone.utc) + timedelta(days=JWT_DAYS),
    }
    return jwt.encode(payload, SECRET, algorithm='HS256')

def decode_token(token):
    return jwt.decode(token, SECRET, algorithms=['HS256'])

def jwt_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        try:
            payload = decode_token(auth[7:])
            g.user_id = int(payload['sub'])  # was stored as string, cast back
            g.user_email = payload['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return wrapper

def own_project(project_id):
    """Returns project row if it belongs to current user, else None."""
    row = get_db().execute(
        'SELECT * FROM projects WHERE id=? AND user_id=?',
        (project_id, g.user_id)
    ).fetchone()
    return row

# ═══════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════
@app.post('/api/auth/register')
def register():
    data = request.get_json() or {}
    email    = (data.get('email') or '').strip()
    password = data.get('password') or ''
    name     = (data.get('display_name') or '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    db = get_db()
    try:
        db.execute(
            'INSERT INTO users (email, password_hash, display_name) VALUES (?,?,?)',
            (email, pw_hash, name or email.split('@')[0])
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 409

    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    token = make_token(user['id'], user['email'])
    return jsonify({'token': token, 'user': _user_dict(user)}), 201

@app.post('/api/auth/login')
def login():
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return jsonify({'error': 'Too many login attempts, try again in 5 minutes'}), 429

    data = request.get_json() or {}
    email    = (data.get('email') or '').strip()
    password = data.get('password') or ''

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash']):
        return jsonify({'error': 'Invalid email or password'}), 401

    db.execute('UPDATE users SET last_login=datetime("now") WHERE id=?', (user['id'],))
    db.commit()
    token = make_token(user['id'], user['email'])
    return jsonify({'token': token, 'user': _user_dict(user)})

@app.get('/api/auth/me')
@jwt_required
def me():
    user = get_db().execute('SELECT * FROM users WHERE id=?', (g.user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': _user_dict(user)})

def _user_dict(row):
    return {'id': row['id'], 'email': row['email'], 'display_name': row['display_name']}

# ═══════════════════════════════════════════════════
# PROJECT ROUTES
# ═══════════════════════════════════════════════════
@app.get('/api/projects')
@jwt_required
def list_projects():
    rows = get_db().execute(
        'SELECT id,name,created_at,updated_at,is_archived FROM projects '
        'WHERE user_id=? AND is_archived=0 ORDER BY updated_at DESC',
        (g.user_id,)
    ).fetchall()
    return jsonify({'projects': [dict(r) for r in rows]})

@app.post('/api/projects')
@jwt_required
def create_project():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Project name is required'}), 400
    if len(name) > 80:
        return jsonify({'error': 'Name too long (max 80 chars)'}), 400

    db = get_db()
    try:
        db.execute(
            'INSERT INTO projects (user_id, name) VALUES (?,?)',
            (g.user_id, name)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A project with this name already exists'}), 409

    row = db.execute(
        'SELECT id,name,created_at,updated_at FROM projects WHERE user_id=? AND name=?',
        (g.user_id, name)
    ).fetchone()
    return jsonify({'project': dict(row)}), 201

@app.patch('/api/projects/<int:pid>')
@jwt_required
def update_project(pid):
    if not own_project(pid):
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json() or {}
    db = get_db()
    if 'name' in data:
        name = (data['name'] or '').strip()
        if not name:
            return jsonify({'error': 'Name cannot be empty'}), 400
        try:
            db.execute('UPDATE projects SET name=?, updated_at=datetime("now") WHERE id=?', (name, pid))
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'A project with this name already exists'}), 409
    if 'is_archived' in data:
        db.execute('UPDATE projects SET is_archived=? WHERE id=?', (int(bool(data['is_archived'])), pid))
        db.commit()
    row = db.execute('SELECT id,name,updated_at FROM projects WHERE id=?', (pid,)).fetchone()
    return jsonify({'project': dict(row)})

@app.delete('/api/projects/<int:pid>')
@jwt_required
def delete_project(pid):
    if not own_project(pid):
        return jsonify({'error': 'Not found'}), 404
    db = get_db()
    db.execute('DELETE FROM projects WHERE id=?', (pid,))
    db.commit()
    return jsonify({'ok': True})

# ═══════════════════════════════════════════════════
# PROJECT DATA ROUTES
# ═══════════════════════════════════════════════════
EMPTY_DATA = {
    'kw_input': '', 'text_input': '', 'old_text_input': '',
    'sort': 'import', 'theme': 'dark', 'compare_mode': 0,
    'meta_columns': '[]', 'keywords': '[]', 'bullet_texts': '[]', 'description_text': '',
}

@app.get('/api/projects/<int:pid>/data')
@jwt_required
def get_project_data(pid):
    if not own_project(pid):
        return jsonify({'error': 'Not found'}), 404
    row = get_db().execute('SELECT * FROM project_data WHERE project_id=?', (pid,)).fetchone()
    data = dict(row) if row else dict(EMPTY_DATA, project_id=pid)
    return jsonify({'data': data})

MAX_PROJECT_BYTES = 500 * 1024  # 500 KB

@app.put('/api/projects/<int:pid>/data')
@jwt_required
def put_project_data(pid):
    if not own_project(pid):
        return jsonify({'error': 'Not found'}), 404
    d = request.get_json() or {}
    total_size = sum(
        len(str(d.get(f) or ''))
        for f in ('kw_input', 'text_input', 'old_text_input', 'keywords', 'bullet_texts', 'description_text')
    )
    if total_size > MAX_PROJECT_BYTES:
        return jsonify({'error': f'Project data too large (max {MAX_PROJECT_BYTES // 1024} KB)'}), 413
    db = get_db()
    db.execute("""
        INSERT INTO project_data (project_id, kw_input, text_input, old_text_input, sort, theme,
            compare_mode, meta_columns, keywords, bullet_texts, description_text, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
        ON CONFLICT(project_id) DO UPDATE SET
            kw_input=excluded.kw_input,
            text_input=excluded.text_input,
            old_text_input=excluded.old_text_input,
            sort=excluded.sort,
            theme=excluded.theme,
            compare_mode=excluded.compare_mode,
            meta_columns=excluded.meta_columns,
            keywords=excluded.keywords,
            bullet_texts=excluded.bullet_texts,
            description_text=excluded.description_text,
            updated_at=excluded.updated_at
    """, (
        pid,
        d.get('kw_input', ''),
        d.get('text_input', ''),
        d.get('old_text_input', ''),
        d.get('sort', 'import'),
        d.get('theme', 'dark'),
        1 if d.get('compare_mode') else 0,
        d.get('meta_columns', '[]'),
        d.get('keywords', '[]'),
        d.get('bullet_texts', '[]'),
        d.get('description_text', ''),
    ))
    # Bump project's updated_at so it floats to top of list
    db.execute("UPDATE projects SET updated_at=datetime('now') WHERE id=?", (pid,))
    db.commit()
    return jsonify({'ok': True, 'updated_at': datetime.now(timezone.utc).isoformat()})

# Init DB when module loads (needed for gunicorn which skips __main__)
init_db()

# ═══════════════════════════════════════════════════
# STATIC FILE SERVING
# ═══════════════════════════════════════════════════
@app.get('/')
def root():
    return send_from_directory(BASE_DIR, 'index.html')

@app.get('/<path:filename>')
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)

# ═══════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f'[Server] Running at http://localhost:{port}')
    print('[Server] Press Ctrl+C to stop')
    app.run(host='0.0.0.0', port=port, debug=False)
