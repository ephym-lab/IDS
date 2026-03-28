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
