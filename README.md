# 🛡️ Network Intrusion Detection System (IDS)

A real-time Network Intrusion Detection System powered by a **TensorFlow/Keras** multi-class classification model trained on the **UNSW-NB15** dataset, served via a **FastAPI** backend with live packet capture, alert management, user authentication, and automated email notifications.

---

## 📂 Project Structure

```
idssysy/
├── ids_backend/
│   ├── main.py            # FastAPI application & all endpoints
│   ├── database.py        # Async SQLite layer (logs, alerts, users tables)
│   ├── auth.py            # JWT authentication & password hashing
│   ├── email_service.py   # SMTP email notification service
│   ├── model.py           # TensorFlow model loader & inference
│   ├── preprocessor.py    # Feature engineering & encoding
│   ├── capture.py         # Live Scapy packet capture thread
│   ├── .env               # Environment config (SMTP, JWT secrets) — not committed
│   ├── requirements.txt   # Python dependencies
│   └── endpoints.md       # Full API endpoint reference
└── README.md
```

---

## ⚙️ Setup & Installation

### 1. Create & activate a virtual environment

```bash
python -m venv tf-env
source tf-env/bin/activate
```

### 2. Install dependencies

```bash
pip install -r ids_backend/requirements.txt
```

### 3. Configure environment variables

Copy the template and fill in your values:

```bash
cp ids_backend/.env.example ids_backend/.env   # or edit .env directly
```

Open `ids_backend/.env` and set:

```env
# JWT Authentication
SECRET_KEY=your-long-random-secret         # generate: python -c "import secrets; print(secrets.token_hex(32))"
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# SMTP Email (Gmail example)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-gmail-app-password      # NOT your account password — see note below
FROM_EMAIL=your-email@gmail.com
FROM_NAME=IDS Alert System
```

> **Gmail App Password**: Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) and generate a 16-character App Password (2-Step Verification must be enabled). Use that instead of your Google account password.

### 4. Run the server

```bash
cd ids_backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive API docs available at: `http://localhost:8000/docs`

---

## 🔐 Authentication

The IDS uses **JWT (JSON Web Token)** bearer authentication. Register an account, log in to receive a token, and include it in protected requests.

### Register a new account

**`POST /auth/signup`**

Creates a new user account. Only requires your name, email and a password.

**Request body:**
```json
{
  "full_name": "Jane Doe",
  "email": "jane@example.com",
  "password": "s3cur3P@ss"
}
```

**Response (`201 Created`):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "full_name": "Jane Doe",
    "email": "jane@example.com",
    "created_at": "2026-04-08T10:00:00+00:00"
  }
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `409 Conflict` | Email is already registered |
| `422 Unprocessable` | Validation error (e.g. password too short, invalid email) |

**Example:**
```bash
curl -X POST http://localhost:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"full_name": "Jane Doe", "email": "jane@example.com", "password": "s3cur3P@ss"}'
```

---

### Log in

**`POST /auth/login`**

Authenticates with email and password. Returns a JWT access token valid for 60 minutes (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES` in `.env`).

**Request body:**
```json
{
  "email": "jane@example.com",
  "password": "s3cur3P@ss"
}
```

**Response (`200 OK`):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "full_name": "Jane Doe",
    "email": "jane@example.com",
    "created_at": "2026-04-08T10:00:00+00:00"
  }
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `401 Unauthorized` | Wrong email or password |

**Example:**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "jane@example.com", "password": "s3cur3P@ss"}'
```

---

### Get current user profile

**`GET /auth/me`**

Returns the profile of the currently authenticated user. Requires a valid JWT token.

**Headers:**
```
Authorization: Bearer <your_access_token>
```

**Response (`200 OK`):**
```json
{
  "id": 1,
  "full_name": "Jane Doe",
  "email": "jane@example.com",
  "created_at": "2026-04-08T10:00:00+00:00"
}
```

**Example:**
```bash
curl http://localhost:8000/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## 📧 Email Notifications

When the model detects a **High severity** attack (`DoS` or `Exploits`), an automated email alert is sent **in the background** to all registered users. The email includes:

- Attack type & severity badge
- Source and destination IP addresses
- ML model confidence score
- Detection timestamp

Email sending is non-blocking — it runs in a thread-pool executor and never delays the API response. If SMTP credentials are not configured in `.env`, sending is silently skipped with a log warning.

**Severity classification:**

| Severity | Attack Types |
|----------|-------------|
| 🔴 **High** | `DoS`, `Exploits` |
| 🟠 **Medium** | `Reconnaissance`, `Generic` |
| 🟡 **Low** | `Fuzzers`, `Other` |

---

## 🌐 API Endpoints Overview

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|:---:|
| `POST` | `/auth/signup` | Register a new user account | ❌ |
| `POST` | `/auth/login` | Log in and receive a JWT token | ❌ |
| `GET` | `/auth/me` | Get current user profile | ✅ |
| `POST` | `/predict` | Single network record prediction | ❌ |
| `POST` | `/upload` | Batch CSV prediction | ❌ |
| `GET` | `/alerts` | Query alert history | ❌ |
| `GET` | `/logs` | Query full traffic logs | ❌ |
| `GET` | `/stats` | Summary statistics | ❌ |
| `POST` | `/capture/start` | Start live packet capture | ❌ |
| `POST` | `/capture/stop` | Stop live packet capture | ❌ |
| `GET` | `/capture/status` | Check capture thread status | ❌ |

For full request/response schemas, see [`ids_backend/endpoints.md`](ids_backend/endpoints.md) or the interactive docs at `http://localhost:8000/docs`.

---

## 🗄️ Database Schema

The backend uses an **async SQLite** database (`ids.db`) with three tables:

| Table | Purpose |
|-------|---------|
| `logs` | Every processed network record (Normal + attacks) |
| `alerts` | Attack detections only, with severity classification |
| `users` | Registered user accounts (bcrypt-hashed passwords) |

---

## 🧠 ML Model

- **Dataset**: UNSW-NB15 (multi-class network intrusion dataset)
- **Architecture**: TensorFlow / Keras neural network
- **Classes**: `Normal`, `DoS`, `Exploits`, `Reconnaissance`, `Generic`, `Fuzzers`, `Other`
- **Preprocessing**: Standard scaling + one-hot encoding via scikit-learn pipelines

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| API Framework | FastAPI + Uvicorn |
| ML | TensorFlow / Keras, Scikit-learn |
| Database | SQLite (async via `aiosqlite`) |
| Auth | JWT (`python-jose`) + bcrypt (`passlib`) |
| Email | Python `smtplib` (STARTTLS / Gmail) |
| Packet Capture | Scapy |
