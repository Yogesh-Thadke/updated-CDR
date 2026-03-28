from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import json
import sqlite3
from functools import wraps
import secrets
import networkx as nx
import math
import io

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config['UPLOAD_FOLDER'] = 'data/uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
app.config['DB_PATH'] = 'data/db/cdr.db'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data/db', exist_ok=True)

current_cdr_data = None
current_suspect_number = None
last_analysis_result = None

# ── DB ─────────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(app.config['DB_PATH'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_name TEXT NOT NULL,
                description TEXT,
                created_by INTEGER,
                csv_filename TEXT,
                suspect_number TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not existing:
            db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       ('admin', generate_password_hash('admin123'), 'admin'))
        db.commit()

init_db()

# ── Helpers ────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def log_action(action, details=''):
    if 'user_id' in session:
        with get_db() as db:
            db.execute("INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)",
                       (session['user_id'], action, details))
            db.commit()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

# ── Auth ───────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            log_action('LOGIN', f'User {username} logged in')
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_action('LOGOUT')
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if session.get('role') != 'admin':
        flash('Only admins can create new users.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'analyst')
        if not username or not password:
            flash('Username and password are required.', 'error')
        else:
            try:
                with get_db() as db:
                    db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                               (username, generate_password_hash(password), role))
                    db.commit()
                flash(f'User {username} created successfully.', 'success')
                log_action('CREATE_USER', f'Created user {username} with role {role}')
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'error')
    with get_db() as db:
        users = db.execute("SELECT id, username, role, created_at FROM users").fetchall()
    return render_template('register.html', users=users)

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    current = data.get('current_password', '')
    new_pw = data.get('new_password', '')
    if not current or not new_pw:
        return jsonify({'error': 'Both fields required'}), 400
    if len(new_pw) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if not check_password_hash(user['password_hash'], current):
        return jsonify({'error': 'Current password is incorrect'}), 400
    with get_db() as db:
        db.execute("UPDATE users SET password_hash=? WHERE id=?",
                   (generate_password_hash(new_pw), session['user_id']))
        db.commit()
    log_action('CHANGE_PASSWORD', 'Password changed')
    return jsonify({'success': True, 'message': 'Password updated successfully'})

# ── Main ───────────────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    with get_db() as db:
        cases = db.execute(
            "SELECT c.*, u.username FROM cases c JOIN users u ON c.created_by=u.id ORDER BY c.created_at DESC LIMIT 10"
        ).fetchall()
    return render_template('index.html', cases=cases)

# ── Upload ─────────────────────────────────────────────────────────────────────
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    global current_cdr_data
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            df = pd.read_csv(filepath)
            required_columns = ['record_id', 'caller_number', 'receiver_number',
                                 'call_type', 'start_time', 'duration_seconds',
                                 'cell_tower_lat', 'cell_tower_lon']
            if not all(col in df.columns for col in required_columns):
                return jsonify({'error': 'Invalid CSV format. Missing required columns.'}), 400
            df['caller_number'] = df['caller_number'].astype(str)
            df['receiver_number'] = df['receiver_number'].astype(str)
            if 'imei' not in df.columns:
                df['imei'] = None
            if 'record_type' not in df.columns:
                df['record_type'] = 'Call'
            current_cdr_data = df
            df['start_time_dt'] = pd.to_datetime(df['start_time'])
            all_numbers = sorted(set(df['caller_number'].tolist() + df['receiver_number'].tolist()))
            log_action('UPLOAD', f'Uploaded {filename} with {len(df)} records')
            return jsonify({
                'success': True,
                'message': f'Loaded {len(df)} records.',
                'phone_numbers': all_numbers,
                'record_count': len(df),
                'date_min': str(df['start_time_dt'].min().date()),
                'date_max': str(df['start_time_dt'].max().date()),
                'has_imei': bool(df['imei'].notna().any()),
                'has_sms': bool((df['record_type'] == 'SMS').any())
            })
        except Exception as e:
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    return jsonify({'error': 'Only CSV files allowed'}), 400

# ── Analyze ────────────────────────────────────────────────────────────────────
@app.route('/analyze', methods=['POST'])
@login_required
def analyze_suspect():
    global current_cdr_data, current_suspect_number, last_analysis_result
    if current_cdr_data is None:
        return jsonify({'error': 'No CDR data loaded. Please upload a file first.'}), 400
    data = request.get_json()
    suspect_number = str(data.get('suspect_number', ''))
    date_from = data.get('date_from', '')
    date_to = data.get('date_to', '')
    record_type_filter = data.get('record_type', 'All')
    if not suspect_number:
        return jsonify({'error': 'Suspect number is required'}), 400
    current_suspect_number = suspect_number
    try:
        df = current_cdr_data.copy()
        df['caller_number'] = df['caller_number'].astype(str)
        df['receiver_number'] = df['receiver_number'].astype(str)
        df['start_time'] = pd.to_datetime(df['start_time'])
        if date_from:
            df = df[df['start_time'] >= pd.to_datetime(date_from)]
        if date_to:
            df = df[df['start_time'] <= pd.to_datetime(date_to) + timedelta(days=1)]
        if record_type_filter != 'All' and 'record_type' in df.columns:
            df = df[df['record_type'] == record_type_filter]

        suspect_records = df[
            (df['caller_number'] == suspect_number) |
            (df['receiver_number'] == suspect_number)
        ].copy()

        if len(suspect_records) == 0:
            return jsonify({'error': 'No records found for this number in the selected filters'}), 404

        log_action('ANALYZE', f'Analyzed {suspect_number} ({len(suspect_records)} records)')

        results = {
            'call_patterns': analyze_call_patterns(suspect_records, suspect_number),
            'frequent_contacts': analyze_frequent_contacts(suspect_records, suspect_number),
            'temporal_analysis': analyze_temporal_patterns(suspect_records),
            'location_data': extract_location_data(suspect_records),
            'tower_movements': analyze_tower_movements(suspect_records),
            'anomalies': detect_anomalies(suspect_records, suspect_number),
            'summary': generate_summary(suspect_records, suspect_number),
            'network_graph': build_network_graph(df, suspect_number),
            'imei_analysis': analyze_imei(suspect_records, suspect_number),
            'sms_analysis': analyze_sms(suspect_records, suspect_number),
        }
        last_analysis_result = results
        return jsonify(results)
    except Exception as e:
        import traceback
        return jsonify({'error': f'Analysis error: {str(e)}', 'trace': traceback.format_exc()}), 500

# ── Analysis Functions ─────────────────────────────────────────────────────────
def analyze_call_patterns(df, suspect_number):
    calls = df[df['record_type'] == 'Call'] if 'record_type' in df.columns else df
    outgoing = calls[calls['caller_number'] == suspect_number]
    incoming = calls[calls['receiver_number'] == suspect_number]
    return {
        'total_calls': len(calls),
        'outgoing_calls': len(outgoing),
        'incoming_calls': len(incoming),
        'call_type_distribution': calls['call_type'].value_counts().to_dict(),
        'total_duration_minutes': round(calls['duration_seconds'].sum() / 60, 2),
        'average_call_duration': round(calls['duration_seconds'].mean(), 2) if len(calls) else 0
    }

def analyze_frequent_contacts(df, suspect_number):
    outgoing = df[df['caller_number'] == suspect_number]['receiver_number']
    incoming = df[df['receiver_number'] == suspect_number]['caller_number']
    contact_freq = pd.concat([outgoing, incoming]).value_counts().head(10)
    contacts = []
    for contact, count in contact_freq.items():
        recs = df[
            ((df['caller_number'] == suspect_number) & (df['receiver_number'] == contact)) |
            ((df['receiver_number'] == suspect_number) & (df['caller_number'] == contact))
        ]
        contacts.append({
            'number': contact, 'call_count': int(count),
            'total_duration_minutes': round(recs['duration_seconds'].sum() / 60, 2),
            'average_duration': round(recs['duration_seconds'].mean(), 2)
        })
    return contacts

def analyze_temporal_patterns(df):
    df = df.copy()
    df['hour'] = df['start_time'].dt.hour
    df['day_of_week'] = df['start_time'].dt.day_name()
    df['date'] = df['start_time'].dt.date
    return {
        'hourly_distribution': df['hour'].value_counts().sort_index().to_dict(),
        'daily_distribution': df['day_of_week'].value_counts().to_dict(),
        'calls_per_day': {str(k): int(v) for k, v in df.groupby('date').size().items()},
        'peak_hour': int(df['hour'].mode()[0]) if len(df) > 0 else 0,
        'busiest_day': df['day_of_week'].mode()[0] if len(df) > 0 else 'N/A'
    }

def extract_location_data(df):
    grp = df.groupby(['cell_tower_lat', 'cell_tower_lon']).agg(
        call_count=('record_id', 'count'),
        first_seen=('start_time', 'min'),
        last_seen=('start_time', 'max')
    ).reset_index()
    return [{'lat': float(r['cell_tower_lat']), 'lon': float(r['cell_tower_lon']),
              'call_count': int(r['call_count']), 'first_seen': str(r['first_seen']),
              'last_seen': str(r['last_seen'])} for _, r in grp.iterrows()]

def analyze_tower_movements(df):
    df = df.copy().sort_values('start_time').reset_index(drop=True)
    movements, alerts = [], []
    for i in range(1, len(df)):
        prev, curr = df.iloc[i-1], df.iloc[i]
        lat1, lon1 = float(prev['cell_tower_lat']), float(prev['cell_tower_lon'])
        lat2, lon2 = float(curr['cell_tower_lat']), float(curr['cell_tower_lon'])
        if lat1 == lat2 and lon1 == lon2:
            continue
        dist_km = haversine_km(lat1, lon1, lat2, lon2)
        time_h = (curr['start_time'] - prev['start_time']).total_seconds() / 3600
        speed = dist_km / time_h if time_h > 0 else 0
        movements.append({'from_time': str(prev['start_time']), 'to_time': str(curr['start_time']),
                          'from_lat': lat1, 'from_lon': lon1, 'to_lat': lat2, 'to_lon': lon2,
                          'distance_km': round(dist_km, 2), 'time_hours': round(time_h, 2),
                          'speed_kmh': round(speed, 1)})
        if speed > 400:
            alerts.append({'severity': 'High',
                'description': f'Impossible movement: {round(dist_km,1)} km in {round(time_h*60,0):.0f} min ({round(speed,0):.0f} km/h) — possible cloned SIM',
                'time': str(curr['start_time'])})
        elif speed > 150:
            alerts.append({'severity': 'Medium',
                'description': f'Rapid movement: {round(dist_km,1)} km in {round(time_h*60,0):.0f} min ({round(speed,0):.0f} km/h)',
                'time': str(curr['start_time'])})
    return {'movements': movements[:50], 'alerts': alerts}

def analyze_imei(df, suspect_number):
    if 'imei' not in df.columns or df['imei'].isna().all():
        return {'available': False}
    suspect_rows = df[(df['caller_number'] == suspect_number) | (df['receiver_number'] == suspect_number)]
    imei_list = suspect_rows['imei'].dropna().unique().tolist()
    imei_numbers = {}
    for imei in imei_list:
        rows = df[df['imei'] == imei]
        imei_numbers[str(imei)] = list(set(rows['caller_number'].tolist() + rows['receiver_number'].tolist()))
    return {'available': True, 'imei_list': [str(i) for i in imei_list],
            'imei_count': len(imei_list), 'sim_swap_suspected': len(imei_list) > 1,
            'imei_numbers': imei_numbers}

def analyze_sms(df, suspect_number):
    if 'record_type' not in df.columns:
        return {'available': False}
    sms = df[df['record_type'] == 'SMS']
    if len(sms) == 0:
        return {'available': False, 'count': 0}
    suspect_sms = sms[(sms['caller_number'] == suspect_number) | (sms['receiver_number'] == suspect_number)]
    sent = suspect_sms[suspect_sms['caller_number'] == suspect_number]
    received = suspect_sms[suspect_sms['receiver_number'] == suspect_number]
    top = pd.concat([sent['receiver_number'], received['caller_number']]).value_counts().head(5).to_dict()
    return {'available': True, 'total_sms': len(suspect_sms), 'sent': len(sent),
            'received': len(received), 'top_sms_contacts': {str(k): int(v) for k, v in top.items()}}

def detect_anomalies(df, suspect_number):
    df = df.copy()
    anomalies = []
    df['hour'] = df['start_time'].dt.hour
    df['date'] = df['start_time'].dt.date

    odd = df[(df['hour'] >= 0) & (df['hour'] < 5)]
    if len(odd) > 5:
        anomalies.append({'type': 'Odd Hours Activity', 'severity': 'Medium',
            'description': f'{len(odd)} calls between midnight and 5 AM', 'count': len(odd)})

    daily = df.groupby('date').size()
    if len(daily) > 1:
        mean_c, std_c = daily.mean(), daily.std()
        for day, count in daily[daily > mean_c + 2 * std_c].items():
            anomalies.append({'type': 'Call Volume Spike', 'severity': 'High',
                'description': f'{int(count)} calls on {day} (avg: {int(mean_c)})', 'date': str(day), 'count': int(count)})

    df_s = df.sort_values('start_time')
    seen, new_per_day = set(), {}
    for _, row in df_s.iterrows():
        contact = row['receiver_number'] if row['caller_number'] == suspect_number else row['caller_number']
        if contact not in seen:
            seen.add(contact)
            d = str(row['date'])
            new_per_day[d] = new_per_day.get(d, 0) + 1
    for day, count in new_per_day.items():
        if count >= 5:
            anomalies.append({'type': 'New Contacts Burst', 'severity': 'Medium',
                'description': f'{count} new contacts on {day}', 'date': day, 'count': count})

    short = df[df['duration_seconds'] < 5]
    if len(short) > 10:
        anomalies.append({'type': 'Short Duration Calls', 'severity': 'Low',
            'description': f'{len(short)} calls under 5 seconds (possible signaling)', 'count': len(short)})

    if 'record_type' in df.columns:
        night_sms = df[(df['record_type'] == 'SMS') & (df['hour'] >= 0) & (df['hour'] < 5)]
        if len(night_sms) > 5:
            anomalies.append({'type': 'Late Night SMS Activity', 'severity': 'Medium',
                'description': f'{len(night_sms)} SMS messages between midnight and 5 AM', 'count': len(night_sms)})

    return anomalies

def generate_summary(df, suspect_number):
    return {
        'suspect_number': suspect_number,
        'total_records': len(df),
        'date_range': {'start': str(df['start_time'].min()), 'end': str(df['start_time'].max())},
        'unique_contacts': len(set(df['caller_number'].tolist() + df['receiver_number'].tolist())) - 1,
        'unique_locations': df[['cell_tower_lat', 'cell_tower_lon']].drop_duplicates().shape[0]
    }

def build_network_graph(df, suspect_number, depth=2):
    G = nx.Graph()
    for _, row in df.iterrows():
        caller, receiver = str(row['caller_number']), str(row['receiver_number'])
        duration = float(row['duration_seconds'])
        if G.has_edge(caller, receiver):
            G[caller][receiver]['weight'] += 1
            G[caller][receiver]['total_duration'] += duration
        else:
            G.add_edge(caller, receiver, weight=1, total_duration=duration)
    if suspect_number not in G:
        return {'nodes': [], 'links': []}
    subgraph_nodes, frontier = set(), {suspect_number}
    for _ in range(depth):
        nf = set()
        for node in frontier:
            if node in G:
                nf |= set(G.neighbors(node)) - subgraph_nodes - frontier
        subgraph_nodes |= frontier
        frontier = nf
    subgraph_nodes |= frontier
    sub = G.subgraph(subgraph_nodes)
    centrality = nx.degree_centrality(sub)
    nodes = [{'id': n, 'degree': sub.degree(n), 'centrality': round(centrality.get(n, 0), 4),
               'group': 0 if n == suspect_number else (1 if G.has_edge(suspect_number, n) else 2)}
             for n in sub.nodes()]
    links = [{'source': u, 'target': v, 'weight': int(d['weight']),
               'total_duration_min': round(d['total_duration']/60, 2)}
             for u, v, d in sub.edges(data=True)]
    return {'nodes': nodes, 'links': links}

# ── Shared Contacts ────────────────────────────────────────────────────────────
@app.route('/shared-contacts', methods=['POST'])
@login_required
def shared_contacts():
    global current_cdr_data
    if current_cdr_data is None:
        return jsonify({'error': 'No data loaded'}), 400
    data = request.get_json()
    s1 = str(data.get('suspect1', ''))
    s2 = str(data.get('suspect2', ''))
    if not s1 or not s2:
        return jsonify({'error': 'Two suspect numbers required'}), 400
    df = current_cdr_data.copy()
    def get_contacts(num):
        return (set(df[df['caller_number'] == num]['receiver_number']) |
                set(df[df['receiver_number'] == num]['caller_number'])) - {num}
    c1, c2 = get_contacts(s1), get_contacts(s2)
    shared = list(c1 & c2 - {s1, s2})
    direct = df[((df['caller_number']==s1)&(df['receiver_number']==s2))|
                ((df['caller_number']==s2)&(df['receiver_number']==s1))].shape[0] > 0
    log_action('SHARED_CONTACTS', f'Compared {s1} and {s2}')
    return jsonify({'suspect1': s1, 'suspect2': s2, 'shared_contacts': shared,
                    'shared_count': len(shared), 'suspect1_only': len(c1-c2),
                    'suspect2_only': len(c2-c1), 'direct_contact': direct})

# ── Event Correlation ──────────────────────────────────────────────────────────
@app.route('/event-correlation', methods=['POST'])
@login_required
def event_correlation():
    global current_cdr_data, current_suspect_number
    if current_cdr_data is None or current_suspect_number is None:
        return jsonify({'error': 'No analysis performed yet'}), 400
    data = request.get_json()
    event_time = data.get('event_time')
    time_window_hours = data.get('time_window', 24)
    try:
        event_dt = pd.to_datetime(event_time)
        df = current_cdr_data.copy()
        df['start_time'] = pd.to_datetime(df['start_time'])
        suspect_records = df[(df['caller_number']==current_suspect_number)|(df['receiver_number']==current_suspect_number)].copy()
        before_start = event_dt - timedelta(hours=time_window_hours)
        after_end = event_dt + timedelta(hours=time_window_hours)
        cb = suspect_records[(suspect_records['start_time']>=before_start)&(suspect_records['start_time']<event_dt)]
        ca = suspect_records[(suspect_records['start_time']>=event_dt)&(suspect_records['start_time']<=after_end)]
        log_action('EVENT_CORRELATION', f'Event at {event_time}, window {time_window_hours}h')
        cols = ['record_id','caller_number','receiver_number','call_type','start_time','duration_seconds']
        return jsonify({'event_time': str(event_dt), 'time_window_hours': time_window_hours,
                        'calls_before': len(cb), 'calls_after': len(ca),
                        'before_details': cb[cols].astype(str).to_dict('records'),
                        'after_details': ca[cols].astype(str).to_dict('records')})
    except Exception as e:
        return jsonify({'error': f'Event correlation error: {str(e)}'}), 500

# ── Save Case ──────────────────────────────────────────────────────────────────
@app.route('/save-case', methods=['POST'])
@login_required
def save_case():
    data = request.get_json()
    case_name = data.get('case_name', '').strip()
    if not case_name:
        return jsonify({'error': 'Case name required'}), 400
    with get_db() as db:
        db.execute("INSERT INTO cases (case_name, description, created_by, suspect_number) VALUES (?, ?, ?, ?)",
                   (case_name, data.get('description',''), session['user_id'], current_suspect_number))
        db.commit()
    log_action('SAVE_CASE', f'Saved case: {case_name}')
    return jsonify({'success': True, 'message': f'Case "{case_name}" saved.'})

# ── Audit Log ──────────────────────────────────────────────────────────────────
@app.route('/audit-log')
@login_required
def audit_log():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    with get_db() as db:
        logs = db.execute(
            "SELECT a.*, u.username FROM audit_log a JOIN users u ON a.user_id=u.id ORDER BY a.timestamp DESC LIMIT 100"
        ).fetchall()
    return jsonify([dict(r) for r in logs])

# ── PDF Export ─────────────────────────────────────────────────────────────────
@app.route('/export-pdf')
@login_required
def export_pdf():
    global last_analysis_result, current_suspect_number
    if last_analysis_result is None:
        return "No analysis to export. Run an analysis first.", 400

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    title_s = ParagraphStyle('T', parent=styles['Title'], fontSize=20,
                              textColor=colors.HexColor('#1d4ed8'), spaceAfter=4, alignment=TA_CENTER)
    sub_s = ParagraphStyle('S', parent=styles['Normal'], fontSize=10,
                            textColor=colors.HexColor('#64748b'), alignment=TA_CENTER, spaceAfter=16)
    h2_s = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=13,
                           textColor=colors.HexColor('#1e293b'), spaceBefore=14, spaceAfter=6)
    normal_s = ParagraphStyle('N', parent=styles['Normal'], fontSize=10, spaceAfter=4)
    footer_s = ParagraphStyle('F', parent=styles['Normal'], fontSize=8,
                               textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)

    r = last_analysis_result
    s = r['summary']
    p = r['call_patterns']
    anomalies = r['anomalies']
    contacts = r['frequent_contacts']
    movements = r['tower_movements']

    def make_table(data, col_widths, header_color='#1d4ed8'):
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor(header_color)),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        return t

    story.append(Paragraph("CDR ANALYSIS REPORT", title_s))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%d %B %Y, %H:%M')} | Analyst: {session['username']} | System: CDR Analysis System v3.0",
        sub_s))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1d4ed8')))
    story.append(Spacer(1, 12))

    story.append(Paragraph("1. Investigation Summary", h2_s))
    story.append(make_table([
        ['Field', 'Value'],
        ['Suspect Number', s['suspect_number']],
        ['Total Records', str(s['total_records'])],
        ['Period', f"{s['date_range']['start'][:10]}  to  {s['date_range']['end'][:10]}"],
        ['Unique Contacts', str(s['unique_contacts'])],
        ['Cell Towers', str(s['unique_locations'])],
        ['Anomalies', str(len(anomalies))],
    ], [6*cm, 10*cm]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("2. Call Pattern Analysis", h2_s))
    story.append(make_table([
        ['Metric', 'Value'],
        ['Total Calls', str(p['total_calls'])],
        ['Outgoing', str(p['outgoing_calls'])],
        ['Incoming', str(p['incoming_calls'])],
        ['Total Talk Time', f"{p['total_duration_minutes']} min"],
        ['Avg Call Duration', f"{p['average_call_duration']} sec"],
    ], [8*cm, 8*cm], '#0ea5e9'))
    story.append(Spacer(1, 10))

    if contacts:
        story.append(Paragraph("3. Top Frequent Contacts", h2_s))
        rows = [['#', 'Number', 'Calls', 'Total (min)', 'Avg (sec)']]
        for i, c in enumerate(contacts[:10], 1):
            rows.append([str(i), c['number'], str(c['call_count']),
                         str(c['total_duration_minutes']), str(c['average_duration'])])
        story.append(make_table(rows, [1*cm, 5.5*cm, 2.5*cm, 4*cm, 4*cm], '#8b5cf6'))
        story.append(Spacer(1, 10))

    story.append(Paragraph("4. Anomaly Detection", h2_s))
    if not anomalies:
        story.append(Paragraph("No suspicious patterns detected.", normal_s))
    else:
        rows = [['Severity', 'Type', 'Description']]
        for a in anomalies:
            rows.append([a['severity'], a['type'], a['description']])
        t = Table(rows, colWidths=[2.5*cm, 5*cm, 9*cm])
        sev_bg = {'High': '#fee2e2', 'Medium': '#fef3c7', 'Low': '#dbeafe'}
        cmds = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]
        for i, a in enumerate(anomalies, 1):
            cmds.append(('BACKGROUND', (0,i), (0,i), colors.HexColor(sev_bg.get(a['severity'],'#ffffff'))))
        t.setStyle(TableStyle(cmds))
        story.append(t)
    story.append(Spacer(1, 10))

    alerts = movements.get('alerts', [])
    if alerts:
        story.append(Paragraph("5. Tower Movement Alerts", h2_s))
        rows = [['Severity', 'Description', 'Time']]
        for a in alerts:
            rows.append([a['severity'], a['description'], a['time'][:19]])
        story.append(make_table(rows, [2.5*cm, 10*cm, 4*cm], '#f59e0b'))
        story.append(Spacer(1, 10))

    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "CONFIDENTIAL — FOR LAW ENFORCEMENT USE ONLY. Generated by CDR Analysis System v3.0. "
        "Findings are based on metadata analysis and must be verified through official channels before use in legal proceedings.",
        footer_s))

    doc.build(story)
    buf.seek(0)
    filename = f"CDR_Report_{current_suspect_number}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    log_action('EXPORT_PDF', f'Exported PDF for {current_suspect_number}')
    return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
