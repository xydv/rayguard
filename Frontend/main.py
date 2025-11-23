from flask import Flask, request, jsonify, session
import joblib
import numpy as np
import requests
import random
import os
from solders.pubkey import Pubkey

app = Flask(__name__)

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
# REQUIRED for session management (U2R logic)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))

HTTPSMS_API_KEY = os.environ.get("HTTPSMS_API_KEY", "your_api_key")
SMS_FROM = os.environ.get("SMS_FROM", "+1234567890")
SMS_TO = os.environ.get("SMS_TO", "+0987654321")

USER_LEDGERS = {}
BANNED_USERS = set()

PROGRAM_ID = Pubkey.from_string("J3zRkAgCWjpXnKUr6teTdS2nLTGA3ZhEUi6gBvi5ZhdY")
BACKEND_URL = "https://laptop.aditya.stream"
MODEL_PATH = "best_intrusion_model.pkl"

try:
    model = joblib.load(MODEL_PATH)
    print(f"✅ Model loaded from {MODEL_PATH}")
except Exception as e:
    print(f"⚠️ Error loading model: {e}")
    model = None

FEATURES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

def preprocess_input(data):
    vector = []
    for f in FEATURES:
        if f not in data:
            # In production, handle missing fields gracefully (e.g., default to 0)
            vector.append(0) 
        else:
            vector.append(data[f])
    return np.array(vector).reshape(1, -1)

def get_or_create_ledger(ip_address):
    if ip_address in USER_LEDGERS:
        return USER_LEDGERS[ip_address]

    seed_int = random.randint(1, 65535)
    seed_bytes = seed_int.to_bytes(2, 'little')
    ledger_pda, _ = Pubkey.find_program_address([b"state", seed_bytes], PROGRAM_ID)
    
    try:
        payload = {"seed": str(seed_int)}
        requests.post(f"{BACKEND_URL}/createLedger", json=payload, timeout=5)
    except Exception:
        pass

    ledger_data = {"pda": str(ledger_pda), "seed": seed_int}
    USER_LEDGERS[ip_address] = ledger_data
    return ledger_data

def post_result_to_external_api(payload):
    try:
        requests.post(f"{BACKEND_URL}/addLog", json=payload, timeout=5)
    except Exception as e:
        print(f"Log Error: {e}")

def send_sms_alert(ip, threat_type):
    url = "https://api.httpsms.com"
    payload = {
        "from": SMS_FROM,
        "to": SMS_TO,
        "content": f"🚨 ALERT: {threat_type} ATTACK DETECTED FROM {ip}. ACTION: LOGGED & NOTIFIED.",
        "encrypted": False
    }
    headers = {"x-api-key": HTTPSMS_API_KEY, "Content-Type": "application/json"}
    try:
        requests.post(url, json=payload, headers=headers, timeout=5)
        print(f"📲 SMS Alert Sent to {SMS_TO}")
    except Exception:
        pass

@app.route("/predict", methods=["POST"])
def predict():
    if not model:
        return jsonify({"error": "Model not loaded"}), 500

    try:
        body = request.get_json()
        ip_address = request.headers.get("ip", request.remote_addr)

        # DOS Logic: Early Rejection
        if ip_address in BANNED_USERS:
             return jsonify({"message": "SERVICE UNAVAILABLE"}), 503

        features = preprocess_input(body)
        prediction_output = model.predict(features)
        
        # Normalize threat type string
        raw_threat = prediction_output[0][0] if isinstance(prediction_output[0], (list, np.ndarray)) else prediction_output[0]
        threat_type = str(raw_threat)

        # Solana Logging
        ledger_info = get_or_create_ledger(ip_address)
        if threat_type not in ["normal", "benign", "Benign Traffic"]:
            post_result_to_external_api({
                "ledger": ledger_info["pda"],
                "ipAddress": ip_address,
                "threatType": threat_type,
                "actionTaken": "Blocked/Alerted"
            })

        # -------------------------------------------------
        # ACTION HANDLERS
        # -------------------------------------------------

        # 1. U2R (User to Root) -> TERMINATE SESSION
        if threat_type == "U2R":
            session.clear()  # Wipes server-side session data
            return jsonify({
                "message": "CRITICAL SECURITY ALERT: SESSION TERMINATED",
                "action": "logout_force" # Frontend should look for this and redirect to login
            }), 403

        # 2. R2L (Remote to Local) -> RELOAD PAGE
        elif threat_type == "R2L":
            # We return a 401 with a specific instruction
            return jsonify({
                "message": "UNAUTHORIZED REQUEST",
                "action": "reload_page" # Frontend should look for this and trigger location.reload()
            }), 401

        # 3. DOS (Denial of Service) -> BAN IP
        elif threat_type == "DOS":
            if ip_address:
                BANNED_USERS.add(ip_address)
            return jsonify({"message": "SERVICE UNAVAILABLE"}), 503

        # 4. PROBE -> SMS ALERT
        elif threat_type == "PROBE":
            send_sms_alert(ip_address, threat_type)
            return jsonify({"message": "PROBE DETECTED: ADMIN NOTIFIED"}), 406

        # 5. NORMAL TRAFFIC
        return jsonify({
            "ledger": ledger_info["pda"],
            "ipAddress": ip_address,
            "threatType": "Benign Traffic",
            "status": "Allowed"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    print("🚀 Security ML API Active...")
    app.run(host="0.0.0.0", port=5000)