# CDR Analysis System v2.0
### Enhanced with Authentication + Network Graph

## What's New in v2.0

| Feature | v1 | v2 |
|---|---|---|
| Authentication | ❌ | ✅ Login / Logout / Role-based |
| User Management | ❌ | ✅ Admin can create analyst accounts |
| Network Graph | ❌ | ✅ D3.js force-directed relationship map |
| Case Saving | ❌ | ✅ Save investigations to SQLite |
| Audit Log | ❌ | ✅ Every action is logged with timestamp |
| Database | ❌ | ✅ SQLite (zero setup) |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate sample data
python generate_sample_data.py

# 3. Run the app
python app.py

# 4. Open browser
http://localhost:5000

# Default login
Username: admin
Password: admin123
```

## Project Structure

```
cdr-analysis-system/
├── app.py                  # Flask backend (all logic)
├── requirements.txt
├── generate_sample_data.py # Generates test CSV
├── templates/
│   ├── login.html          # Auth page
│   ├── register.html       # User management (admin only)
│   └── index.html          # Main dashboard
└── data/
    ├── uploads/            # Uploaded CSV files
    ├── db/                 # SQLite database (auto-created)
    └── sample_cdr_data.csv # Generated test data
```

## API Endpoints

| Route | Auth | Description |
|---|---|---|
| GET / | ✅ | Main dashboard |
| GET /login | ❌ | Login page |
| POST /login | ❌ | Authenticate |
| GET /logout | ✅ | Sign out |
| GET/POST /register | ✅ Admin | User management |
| POST /upload | ✅ | Upload CDR CSV |
| POST /analyze | ✅ | Run full analysis |
| POST /event-correlation | ✅ | Correlate around event |
| POST /save-case | ✅ | Save investigation |
| GET /audit-log | ✅ Admin | View audit trail |

## Tech Stack

- **Backend**: Python 3.8+, Flask, Pandas, NumPy, NetworkX
- **Frontend**: HTML5, Chart.js, D3.js, Leaflet.js
- **Database**: SQLite (via Python stdlib)
- **Auth**: Werkzeug password hashing, Flask session

## Network Graph

The network graph uses D3.js force simulation:
- **Red node** = suspect (center)
- **Yellow nodes** = direct contacts (depth 1)
- **Grey nodes** = secondary contacts (depth 2)
- **Edge thickness** = call frequency
- Drag nodes, scroll to zoom, hover for details

## Roles

- **admin**: Full access — view audit log, create users, all analysis
- **analyst**: Can upload, analyze, save cases — cannot manage users

## Deployment (Production)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Change `app.secret_key` in app.py to a fixed secret for production.
