# Network IDS API Endpoints

This document provides a detailed overview of the available endpoints in the Network Intrusion Detection System (IDS) FastAPI backend.

**Base URL**: `http://localhost:8000`

---

## 1. Prediction Endpoints

### `POST /predict`
Performs a single-record classification on raw network features.

*   **Description**: Analyzes a single network flow record and determines if it is an attack. The result is automatically persisted to the database logs and alerts.
*   **Attack Categories**: `Normal`, `DoS`, `Exploits`, `Reconnaissance`, `Generic`, `Fuzzers`, `Other` (exactly as produced by the trained LabelEncoder).
*   **Request Body**: `application/json`
    ```json
    {
      "dur": 0.001,
      "spkts": 2,
      "dpkts": 2,
      "sbytes": 140,
      "dbytes": 140,
      "rate": 2000,
      "sttl": 31,
      "dttl": 29,
      "sload": 560000,
      "dload": 560000,
      "sinpkt": 0.001,
      "dinpkt": 0.001,
      "sjit": 0,
      "djit": 0,
      "swin": 255,
      "stcpb": 0,
      "dtcpb": 0,
      "dwin": 255,
      "smean": 70,
      "dmean": 70,
      "ct_srv_src": 1,
      "ct_state_ttl": 0,
      "ct_dst_ltm": 1,
      "ct_src_dport_ltm": 1,
      "ct_dst_sport_ltm": 1,
      "ct_dst_src_ltm": 1,
      "is_ftp_login": 0,
      "ct_ftp_cmd": 0,
      "ct_flw_http_mthd": 0,
      "ct_src_ltm": 1,
      "ct_srv_dst": 1,
      "is_sm_ips_ports": 0,
      "proto": "tcp",
      "service": "http",
      "state": "FIN",
      "src_ip": "192.168.1.5",
      "dst_ip": "192.168.1.10"
    }
    ```
*   **Response Body**:
    ```json
    {
      "predicted_class": "Normal",
      "confidence": 0.9998,
      "is_attack": false,
      "severity": null
    }
    ```

*   **Example Usage**:
    ```bash
    curl -X POST http://localhost:8000/predict \
      -H "Content-Type: application/json" \
      -d '{
        "dur": 0.001, "spkts": 2, "dpkts": 2, "sbytes": 140, "dbytes": 140,
        "rate": 2000, "sttl": 31, "dttl": 29, "sload": 560000, "dload": 560000,
        "sinpkt": 0.001, "dinpkt": 0.001, "sjit": 0, "djit": 0, "swin": 255,
        "stcpb": 0, "dtcpb": 0, "dwin": 255, "smean": 70, "dmean": 70,
        "ct_srv_src": 1, "ct_state_ttl": 0, "ct_dst_ltm": 1, "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1, "ct_dst_src_ltm": 1, "is_ftp_login": 0,
        "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "ct_src_ltm": 1, "ct_srv_dst": 1,
        "is_sm_ips_ports": 0, "proto": "tcp", "service": "http", "state": "FIN"
      }'
    ```

### `POST /upload`
Batch classification via CSV file upload.

*   **Description**: Accepts a CSV file containing network flow records (matching the `PredictRequest` fields). It processes each row and returns a summary of the batch results.
*   **Request**: `multipart/form-data`
    *   `file`: The CSV file.
*   **Response Body**:
    ```json
    {
      "total_records": 100,
      "processed": 98,
      "errors": 2,
      "attack_counts": {
        "DoS": 5,
        "Exploits": 2
      },
      "results": [...]
    }
    ```

---

## 2. History & Statistics Endpoints

### `GET /alerts`
Retrieve detected security alerts from the database.

*   **Description**: Returns a list of all detected attacks (non-Normal classes), sorted by newest first.
*   **Query Parameters**:
    *   `limit` (int, default 100): Number of records to return.
    *   `severity` (string): Filter by "High", "Medium", or "Low".
*   **Response Body**:
    ```json
    {
      "count": 1,
      "alerts": [
        {
          "id": 1,
          "timestamp": "2024-03-27T12:00:00Z",
          "src_ip": "1.2.3.4",
          "dst_ip": "5.6.7.8",
          "attack_type": "DoS",
          "confidence": 0.985,
          "severity": "High"
        }
      ]
    }
    ```

### `GET /logs`
Retrieve full traffic logs from the database.

*   **Description**: Returns all processed traffic records (both Normal and Attack), sorted by newest first.
*   **Query Parameters**:
    *   `limit` (int, default 100): Number of records to return.
    *   `from_time` (string, ISO-8601): Filter logs newer than this timestamp.
*   **Response Body**:
    ```json
    {
      "count": 10,
      "logs": [...]
    }
    ```

### `GET /stats`
Get summary statistics for the dashboard.

*   **Description**: Returns current counts for total traffic, attack distribution, and alerts triggered today.
*   **Response Body**:
    ```json
    {
      "total_traffic": 5000,
      "attacks_by_class": {
        "DoS": 12,
        "Fuzzers": 4
      },
      "alerts_today": 16
    }
    ```

---

## 3. Live Capture Endpoints

### `POST /capture/start`
Starts real-time packet sniffing in the background.

*   **Description**: Spins up a background thread using Scapy to capture live network traffic and feed it into the detection model.
*   **Response** (capture was not running):
    ```json
    {"status": "started", "capturing": true}
    ```
*   **Response** (capture was already running):
    ```json
    {"status": "already_running", "capturing": true}
    ```

### `POST /capture/stop`
Stops the live packet sniffing thread.

*   **Response** (capture was running):
    ```json
    {"status": "stopped", "capturing": false}
    ```
*   **Response** (capture was not running):
    ```json
    {"status": "not_running", "capturing": false}
    ```

### `GET /capture/status`
Checks if the live capture thread is currently running.

*   **Response**: `{"capturing": true}`

---

## 4. Authentication Endpoints

Authentication uses a **2-step OTP flow** for regular users. Admins bypass OTP entirely and receive a JWT on the first request.

> **OTP policy**: Codes are 6 digits, valid for **10 minutes**, single-use, and stored hashed with bcrypt.

> **Roles**: `"admin"` — bypasses OTP and admin-approval gate. `"user"` — must complete OTP then wait for admin approval.

---

### `POST /auth/signup` — Step 1

Register a new user account and trigger an OTP email.

*   **Description**: Creates a pending (unverified) user, then emails a 6-digit OTP. The account is only activated after successful OTP verification.
*   **Request Body**: `application/json`
    ```json
    {
      "full_name": "Jane Doe",
      "email": "jane@example.com",
      "password": "s3cur3P@ss"
    }
    ```
*   **Response Body** (`202 Accepted`):
    ```json
    {
      "message": "OTP sent to jane@example.com. Enter it to complete signup."
    }
    ```
*   **Error Responses**:
    *   `409 Conflict` — email already registered and verified
    *   `422 Unprocessable Entity` — validation failure (short password, invalid email)
*   **Example**:
    ```bash
    curl -X POST http://localhost:8000/auth/signup \
      -H "Content-Type: application/json" \
      -d '{"full_name": "Jane Doe", "email": "jane@example.com", "password": "s3cur3P@ss"}'
    ```

---

### `POST /auth/signup/verify-otp` — Step 2

Verify the signup OTP and activate the account.

*   **Description**: Accepts the 6-digit code from the signup email. On success, marks the user as verified and returns a JWT access token.
*   **Request Body**: `application/json`
    ```json
    {
      "email": "jane@example.com",
      "otp": "482913"
    }
    ```
*   **Response Body** (`201 Created`):
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer",
      "user": {
        "id": 1,
        "full_name": "Jane Doe",
        "email": "jane@example.com",
        "role": "user",
        "created_at": "2026-04-19T20:00:00+00:00"
      }
    }
    ```
> **Note**: After signup the account is `is_verified = 1` but requires **admin approval** before the user can log in.
*   **Error Responses**:
    *   `400 Bad Request` — no OTP was issued for this email
    *   `401 Unauthorized` — incorrect OTP or OTP has expired
    *   `404 Not Found` — no pending signup for this email

---

### `POST /auth/login` — Step 1

Authenticate with email + password.

*   **Description**:
    - **Admin** (`role = "admin"`): JWT is returned immediately — **no OTP step**.
    - **Regular user**: a 6-digit OTP is emailed; client must call `/auth/login/verify-otp`.
*   **Request Body**: `application/json`
    ```json
    {
      "email": "jane@example.com",
      "password": "s3cur3P@ss"
    }
    ```
*   **Response — regular user** (`200 OK`):
    ```json
    {
      "message": "OTP sent to jane@example.com. Enter it to complete login."
    }
    ```
*   **Response — admin** (`200 OK`):
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer",
      "user": {
        "id": 1,
        "full_name": "Admin",
        "email": "admin@ids.com",
        "role": "admin",
        "created_at": "2026-04-19T20:00:00+00:00"
      }
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` — wrong email or password
    *   `403 Forbidden` — account not OTP-verified, or pending admin approval
*   **Example**:
    ```bash
    curl -X POST http://localhost:8000/auth/login \
      -H "Content-Type: application/json" \
      -d '{"email": "jane@example.com", "password": "s3cur3P@ss"}'
    ```

---

### `POST /auth/login/verify-otp` — Step 2

Verify the login OTP and receive a JWT.

*   **Description**: Accepts the 6-digit code from the login email. On success, clears the OTP and returns a JWT access token.
*   **Request Body**: `application/json`
    ```json
    {
      "email": "jane@example.com",
      "otp": "371042"
    }
    ```
*   **Response Body** (`200 OK`):
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer",
      "user": {
        "id": 2,
        "full_name": "Jane Doe",
        "email": "jane@example.com",
        "role": "user",
        "created_at": "2026-04-19T20:00:00+00:00"
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` — no active OTP (user must call `/auth/login` first)
    *   `401 Unauthorized` — incorrect OTP or OTP has expired

---

### `POST /auth/resend-otp`

Resend a fresh OTP to the given email.

*   **Description**: Regenerates and re-emails the OTP. Works for both unverified (signup) and verified (login) accounts. Always returns the same generic response to avoid email enumeration.
*   **Request Body**: `application/json`
    ```json
    {
      "email": "jane@example.com"
    }
    ```
*   **Response Body** (`200 OK`):
    ```json
    {
      "message": "If jane@example.com is registered, a new OTP has been sent."
    }
    ```

---

### `GET /auth/me`

Get the currently authenticated user's profile.

*   **Description**: Decodes the bearer token and returns the user's stored profile. Requires `is_verified = 1` and `admin_verified = 1` (admins are always trusted).
*   **Headers**: `Authorization: Bearer <access_token>`
*   **Response Body** (`200 OK`):
    ```json
    {
      "id": 1,
      "full_name": "Jane Doe",
      "email": "jane@example.com",
      "role": "user",
      "created_at": "2026-04-19T20:00:00+00:00"
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` — missing, expired, or invalid token
    *   `403 Forbidden` — account not OTP-verified, or pending admin approval
*   **Example**:
    ```bash
    curl http://localhost:8000/auth/me \
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```

---


## 5. Admin Endpoints

All admin endpoints require a valid JWT with `role = 'admin'`. An admin user must be created manually in the database (see below).

> **Creating the first admin** — run the following one-liner in the `ids_backend/` folder (replace the values as needed):
> ```bash
> python - <<'EOF'
> import asyncio, database, auth
> asyncio.run(database.init_db())
> asyncio.run(database.create_user(
>     full_name="Admin",
>     email="admin@example.com",
>     hashed_password=auth.hash_password("YourStrongP@ss"),
>     is_verified=True,
>     admin_verified=True,
>     role="admin",
> ))
> print("Admin created.")
> EOF
> ```

---

### `GET /admin/users`

List every registered user.

*   **Headers**: `Authorization: Bearer <admin_token>`
*   **Response Body** (`200 OK`):
    ```json
    {
      "count": 3,
      "users": [
        {
          "id": 2,
          "full_name": "Jane Doe",
          "email": "jane@example.com",
          "is_verified": 1,
          "admin_verified": 0,
          "role": "user",
          "created_at": "2026-04-19T20:00:00+00:00"
        }
      ]
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` — missing or invalid token
    *   `403 Forbidden` — caller is not an admin

---

### `GET /admin/users/pending`

List users who completed OTP verification but are awaiting admin approval.

*   **Headers**: `Authorization: Bearer <admin_token>`
*   **Response Body** (`200 OK`): same shape as `/admin/users` but filtered to `is_verified=1, admin_verified=0, role='user'`.

---

### `POST /admin/users/{user_id}/approve`

Grant system access to a user.

*   **Headers**: `Authorization: Bearer <admin_token>`
*   **Path Parameter**: `user_id` — integer user ID
*   **Response Body** (`200 OK`):
    ```json
    { "message": "User 2 approved successfully." }
    ```

---

### `POST /admin/users/{user_id}/revoke`

Suspend a user's system access without deleting their account.

*   **Headers**: `Authorization: Bearer <admin_token>`
*   **Path Parameter**: `user_id` — integer user ID
*   **Response Body** (`200 OK`):
    ```json
    { "message": "User 2 access revoked." }
    ```

---


## 6. Feedback System Endpoints

Users can submit, edit, and delete their own feedback. Admins can view all feedback across all users and update the status of each entry.

> **Feedback categories**: `bug` | `suggestion` | `general`
>
> **Feedback statuses**: `open` → `reviewed` → `resolved` / `dismissed`

All endpoints require `Authorization: Bearer <access_token>`.

---

### `POST /feedback`
Submit a new feedback entry.

*   **Auth**: Any verified & approved user
*   **Request Body**: `application/json`
    ```json
    {
      "title": "False positive on normal HTTP traffic",
      "message": "The model is flagging regular HTTP GET requests as DoS attacks. This seems like a miscalibration for high-volume traffic.",
      "category": "bug"
    }
    ```
*   **Fields**:
    *   `title` (string, required): 3–200 characters
    *   `message` (string, required): minimum 10 characters
    *   `category` (string, optional, default `"general"`): must be `bug`, `suggestion`, or `general`
*   **Response Body** (`201 Created`):
    ```json
    {
      "message": "Feedback submitted successfully.",
      "feedback": {
        "id": 1,
        "user_id": 3,
        "title": "False positive on normal HTTP traffic",
        "message": "The model is flagging regular HTTP GET requests as DoS attacks...",
        "category": "bug",
        "status": "open",
        "created_at": "2026-04-23T12:00:00+00:00",
        "updated_at": "2026-04-23T12:00:00+00:00"
      }
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` — missing or invalid token
    *   `403 Forbidden` — account not approved
    *   `422 Unprocessable Entity` — validation failure (e.g. title too short, invalid category)
*   **Example**:
    ```bash
    curl -X POST http://localhost:8000/feedback \
      -H "Authorization: Bearer <token>" \
      -H "Content-Type: application/json" \
      -d '{"title": "False positive", "message": "Regular HTTP flagged as DoS.", "category": "bug"}'
    ```

---

### `GET /feedback`
List your own feedback entries.

*   **Auth**: Any verified & approved user
*   **Query Parameters**:
    *   `limit` (int, default `100`, max `1000`): Number of entries to return
*   **Response Body** (`200 OK`):
    ```json
    {
      "count": 2,
      "feedbacks": [
        {
          "id": 2,
          "user_id": 3,
          "title": "Add dark mode toggle",
          "message": "A dark mode for the dashboard would reduce eye strain during night shifts.",
          "category": "suggestion",
          "status": "open",
          "created_at": "2026-04-23T13:00:00+00:00",
          "updated_at": "2026-04-23T13:00:00+00:00"
        }
      ]
    }
    ```
*   **Example**:
    ```bash
    curl http://localhost:8000/feedback \
      -H "Authorization: Bearer <token>"
    ```

---

### `PUT /feedback/{feedback_id}`
Update your own feedback entry.

*   **Auth**: Any verified & approved user (owner only)
*   **Path Parameter**: `feedback_id` — integer feedback ID
*   **Request Body**: `application/json` — all fields are optional; only provided fields are updated
    ```json
    {
      "title": "Updated title",
      "message": "Updated message with more detail.",
      "category": "suggestion"
    }
    ```
*   **Response Body** (`200 OK`):
    ```json
    {
      "message": "Feedback updated successfully.",
      "feedback": {
        "id": 1,
        "user_id": 3,
        "title": "Updated title",
        "message": "Updated message with more detail.",
        "category": "suggestion",
        "status": "open",
        "created_at": "2026-04-23T12:00:00+00:00",
        "updated_at": "2026-04-23T14:30:00+00:00"
      }
    }
    ```
*   **Error Responses**:
    *   `403 Forbidden` — feedback belongs to a different user
    *   `404 Not Found` — feedback ID does not exist
*   **Example**:
    ```bash
    curl -X PUT http://localhost:8000/feedback/1 \
      -H "Authorization: Bearer <token>" \
      -H "Content-Type: application/json" \
      -d '{"title": "Updated title"}'
    ```

---

### `DELETE /feedback/{feedback_id}`
Permanently delete your own feedback entry.

*   **Auth**: Any verified & approved user (owner only)
*   **Path Parameter**: `feedback_id` — integer feedback ID
*   **Response Body** (`200 OK`):
    ```json
    { "message": "Feedback 1 deleted successfully." }
    ```
*   **Error Responses**:
    *   `403 Forbidden` — feedback belongs to a different user
    *   `404 Not Found` — feedback ID does not exist
*   **Example**:
    ```bash
    curl -X DELETE http://localhost:8000/feedback/1 \
      -H "Authorization: Bearer <token>"
    ```

---

### `GET /admin/feedbacks`
List all feedback entries across all users.

*   **Auth**: Admin only
*   **Query Parameters**:
    *   `limit` (int, default `200`, max `1000`): Max entries to return
    *   `status` (string, optional): Filter by `open`, `reviewed`, `resolved`, or `dismissed`
    *   `category` (string, optional): Filter by `bug`, `suggestion`, or `general`
*   **Response Body** (`200 OK`):
    ```json
    {
      "count": 5,
      "feedbacks": [
        {
          "id": 3,
          "user_id": 4,
          "title": "Crash when uploading empty CSV",
          "message": "Uploading an empty CSV file causes a 500 error.",
          "category": "bug",
          "status": "open",
          "created_at": "2026-04-23T09:00:00+00:00",
          "updated_at": "2026-04-23T09:00:00+00:00"
        }
      ]
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` — invalid `status` or `category` value
    *   `403 Forbidden` — caller is not an admin
*   **Example**:
    ```bash
    curl "http://localhost:8000/admin/feedbacks?status=open&category=bug" \
      -H "Authorization: Bearer <admin_token>"
    ```

---

### `PATCH /admin/feedbacks/{feedback_id}/status`
Update the triage status of a feedback entry.

*   **Auth**: Admin only
*   **Path Parameter**: `feedback_id` — integer feedback ID
*   **Request Body**: `application/json`
    ```json
    { "status": "reviewed" }
    ```
*   **Allowed status values**: `open` | `reviewed` | `resolved` | `dismissed`
*   **Response Body** (`200 OK`):
    ```json
    {
      "message": "Feedback 3 status updated to 'reviewed'.",
      "feedback": {
        "id": 3,
        "user_id": 4,
        "title": "Crash when uploading empty CSV",
        "message": "Uploading an empty CSV file causes a 500 error.",
        "category": "bug",
        "status": "reviewed",
        "created_at": "2026-04-23T09:00:00+00:00",
        "updated_at": "2026-04-23T15:00:00+00:00"
      }
    }
    ```
*   **Error Responses**:
    *   `403 Forbidden` — caller is not an admin
    *   `404 Not Found` — feedback ID does not exist
    *   `422 Unprocessable Entity` — invalid status value
*   **Example**:
    ```bash
    curl -X PATCH http://localhost:8000/admin/feedbacks/3/status \
      -H "Authorization: Bearer <admin_token>" \
      -H "Content-Type: application/json" \
      -d '{"status": "resolved"}'
    ```

---

## 7. Email Notification Behaviour

Email alerts are triggered **automatically** — no dedicated endpoint is needed. The flow is:

1. A prediction is made (via `/predict` or `/upload`)
2. If the class is `DoS` or `Exploits` (severity = **High**)
3. All registered user emails are fetched from the database
4. A richly-formatted HTML alert email is dispatched **in the background** (non-blocking)

Configure SMTP credentials in `ids_backend/.env` before expecting emails to arrive. See the [README](../README.md#email-notifications) for setup instructions.

