from flask import Flask, request, jsonify, render_template, send_from_directory
import base64, json, logging, time, requests, threading
from collections import deque
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import mysql.connector
import re
from flask import abort

# Strict zapID pattern: 43 or 44 chars of base64url-safe (Fusion-like zapIDs)
ZAPID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,44}$")

# Common SQL injection keywords/patterns
SQLI_BLACKLIST = [
    "'", '"', "--", ";", "/*", "*/", "#",
    " or ", " and ", " union ", "select ", "insert ",
    "drop ", "update ", "delete ", "shutdown ", "exec ",
    "xp_", "waitfor ", "sleep(", "benchmark(", "information_schema",
]

def validate_zapID(zid: str) -> bool:
    if not isinstance(zid, str) or not ZAPID_PATTERN.fullmatch(zid):
        logging.warning(f"❌ zapID failed pattern match: {zid}")
        return False
    lower = zid.lower()
    if any(bad in lower for bad in SQLI_BLACKLIST):
        logging.warning(f"❌ zapID matched SQLi blacklist: {zid}")
        return False
    return True


locked_zapids = set()
zap_lock = threading.Lock()
pending_commands = {}

db_config = {
    'host': 'stash88.mysql.pythonanywhere-services.com',
    'user': 'stash88',
    'password': 'xlvqqvlx',
    'database': 'stash88$default'
}

app = Flask(__name__)
logging.basicConfig(filename='/home/stash88/zc/zapdebug.log', level=logging.DEBUG)

# === Replay protection ===
NONCE_LIMIT = 100
used_nonces = deque(maxlen=NONCE_LIMIT)

def lock_zap_id(zid):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO locked_zapids (zap_id) VALUES (%s) ON DUPLICATE KEY UPDATE zap_id = zap_id",
            (zid,)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return "zapID locked"
    except Exception as e:
        return f"Error: {e}"

def unlock_zap_id(zid):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM locked_zapids WHERE zap_id = %s", (zid,))
        conn.commit()
        cursor.close()
        conn.close()
        return "zapID unlocked"
    except Exception as e:
        return f"Error: {e}"

def is_zap_id_locked(zid):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM locked_zapids WHERE zap_id = %s", (zid,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result is not None
    except Exception as e:
        logging.error(f"DB check failed for zap_id {zid}: {e}")
        return False

def log_locked_zapids():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT zap_id FROM locked_zapids")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        logging.info(f"Current locked zapIDs: {[r[0] for r in rows]}")
    except Exception as e:
        logging.error(f"Failed to log locked zapIDs: {e}")

def log_locked_zapids():
    # Log the contents of the locked_zapids set
    logging.info(f"Current locked zapIDs: {locked_zapids}")

def add_nonce(nonce):
    used_nonces.append(nonce)

def is_replay(nonce):
    return nonce in used_nonces

# === Base64URL decoding ===
def b64url_decode(data):
    padding = '=' * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)

# === Load private key for optional signed response ===
with open("/home/stash88/zc/rsa_private.pem", "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

@app.route("/check-locks")
def check_locks():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT zap_id FROM locked_zapids")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({
            "locked_zapids": [r[0] for r in rows],
            "count": len(rows),
            "status": "ok"
        })
    except Exception as e:
        logging.error(f"/check-locks failed: {e}")
        return jsonify({"status": "error", "reason": str(e)}), 500

"""
@app.route("/manual-lock")
def manual_lock():
    zid = "cczsAcwp5sB4o1WZgf9MPgq9LUMcRcZ9JQLVPpP8T-I"
    with zap_lock:
        logging.info("manual_lock********")
        log_locked_zapids()
        result = lock_zap_id(zid)
        logging.info(f"{result}")
        command_payload = {
            "action": "updateLock",
            "locked": True,
            "zapID": zid
        }
        logging.info(f"Sending updateLock command: {command_payload}")
    log_locked_zapids()
    return "*** Lock sent ***"

@app.route('/manual-unlock')
def manual_unlock():
    zid = "cczsAcwp5sB4o1WZgf9MPgq9LUMcRcZ9JQLVPpP8T-I"
    with zap_lock:
        logging.info("manual_unlock********")
        log_locked_zapids()
        result = unlock_zap_id(zid)
        logging.info(f"{result}")
        command_payload = {
            "action": "updateLock",
            "locked": False,
            "zapID": zid
        }
        logging.info(f"Sending updateLock command: {command_payload}")
    log_locked_zapids()
    return "*** Unlock sent ***"
"""

@app.route("/manual-lock")
def manual_lock():
    zid = request.values.get("zid", "").strip()
    print(">>>> /manual-lock GET zid =", zid)

    if not zid or not validate_zapID(zid):
        logging.warning(f"Rejected invalid zapID on /manual-lock: {zid}")
        return "Invalid zapID", 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT IGNORE INTO locked_zapids (zap_id) VALUES (%s)", (zid,))
        conn.commit()
        cursor.close()
        conn.close()
        return "", 200
    except Exception as e:
        logging.error(f"MySQL error during lock: {e}")
        return "ZapCaptain: Database error", 500


@app.route("/manual-unlock")
def manual_unlock():
    zid = request.values.get("zid", "").strip()
    print(">>>> /manual-unlock GET zid =", zid)

    if not zid or not validate_zapID(zid):
        logging.warning(f"Rejected invalid zapID on /manual-unlock: {zid}")
        return "Invalid zapID", 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM locked_zapids WHERE zap_id = %s", (zid,))
        conn.commit()
        cursor.close()
        conn.close()
        return "", 200
    except Exception as e:
        logging.error(f"MySQL error during unlock: {e}")
        return "ZapCaptain: Database error", 500

def send_manual_zap_command(event="zapLockout", zap_id="manual-test", fingerprint="test-fp"):
    try:
        timestamp = int(time.time() * 1000)
        nonce = f"{event}-{timestamp}"

        # === Generate ephemeral keypair ===
        ephemeral_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        ephemeral_public = ephemeral_private.public_key()
        public_numbers = ephemeral_public.public_numbers()

        # Generate ephemeral JWK to send (public only)
        e_b64 = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode().rstrip("=")
        n_b64 = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode().rstrip("=")

        payload = {
            "event": event,
            "zapID": zap_id,
            "fingerprint": fingerprint,
            "timestamp": timestamp,
            "nonce": nonce
        }

        # Sign with ephemeral private key
        serialized = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        sig = base64.urlsafe_b64encode(
            ephemeral_private.sign(serialized, padding.PKCS1v15(), hashes.SHA256())
        ).decode("utf-8").rstrip("=")

        ephemeral = {
            "kty": "RSA",
            "e": e_b64,
            "n": n_b64
        }

        # Send
        #resp = app.test_client().post("/zapcapture", json={
        #    "payload": payload,
        #    "signature": sig,
        #    "ephemeral": ephemeral
        #})
        with app.test_request_context("/zapcapture", method="POST", json={
            "payload": payload,
            "signature": sig,
            "ephemeral": ephemeral
        }):
            resp = zapcapture()

        # Queue command to be returned on next zapVerify
        #pending_commands[zap_id] = {
        #    "payload": payload,
        #    "queued_at": time.time()
        #}

        # Log and check if the request was successful
        if resp.status_code != 200:
            logging.error(f"[{event}] failed to send command. Status code: {resp.status_code} Response: {resp.text}")
            return {"status": "error", "reason": "Failed to send command"}

        logging.info(f"[{event}] command sent successfully for zapID: {zap_id}")
        #return resp.get_json()
        return resp.get_json() if hasattr(resp, "get_json") else resp

        #logging.info("[%s] status=%s → %s", event.upper(), resp.status_code, resp.get_json())
        #return resp.get_json()
        #logging.info("Manual %s command queued for zapID: %s", event, zap_id)
        #return {"queued": event, "zapID": zap_id}

    except Exception as ex:
        logging.exception("Manual %s failed", event.upper())
        return {"error": str(ex)}

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/nonces')
def show_nonces():
    return jsonify({"recent_nonces": list(used_nonces)})

@app.route('/telemetry')
def show_telemetry():
    #return jsonify({"telemetry": list(telemetry_log)})
    return jsonify({"telemetry": list(reversed(telemetry_log))})

# === Captured telemetry log for debugging ===
telemetry_log = []

@app.route('/zapcapture', methods=['POST'])
def zapcapture():
    global locked_zapids  # Track locked zapIDs
    try:
        data = request.get_json(force=True)
        logging.debug("Incoming data:", data)
        print("INCOMING JSON:", data)

        if not data or not all(k in data for k in ("payload", "signature", "ephemeral")):
            logging.warning("Missing fields in POST data: %s", data)
            return jsonify({"status": "error", "reason": "Missing required fields"}), 400

        payload = data["payload"]
        signature_b64 = data["signature"]
        ephemeral_jwk = data["ephemeral"]

        nonce = payload.get("nonce", "").strip()
        event = payload.get("event", "").strip()
        zap_id = payload.get("zapID", "").strip()
        timestamp = payload.get("timestamp")
        fingerprint = payload.get("fingerprint", "").strip()

        # === Validate presence of required fields ===
        if not all([nonce, event, zap_id, fingerprint, timestamp]):
            return jsonify({"status": "error", "reason": "Missing required fields"}), 400

        # === Deserialize & verify signature ===
        serialized_payload = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        e_bytes = b64url_decode(ephemeral_jwk["e"])
        n_bytes = b64url_decode(ephemeral_jwk["n"])
        ephemeral_key = rsa.RSAPublicNumbers(
            e=int.from_bytes(e_bytes, byteorder="big"),
            n=int.from_bytes(n_bytes, byteorder="big")
        ).public_key(default_backend())

        signature = b64url_decode(signature_b64)
        try:
            ephemeral_key.verify(
                signature,
                serialized_payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            # Allow internal (manual) commands with a known magic fingerprint
            if fingerprint == "test-fp":
                logging.warning("Bypassing signature check for manual command")
            else:
                logging.exception("Signature verification failed for zapID %s (nonce=%s)", zap_id, nonce)
                return jsonify({"status": "error", "reason": "Invalid signature"}), 400

        logging.info("✔ Signature verified for zapID %s (nonce=%s)", zap_id, nonce)

        # === Replay protection ===
        if is_replay(nonce) and event != "zapUnlock":
            logging.warning("Replay detected for zapID %s (nonce=%s)", zap_id, nonce)
            return jsonify({"status": "error", "reason": "Replay detected"}), 400
        add_nonce(nonce)

        # === Timestamp validation ===
        now = time.time()
        if abs(now - timestamp / 1000.0) > 10:
            logging.warning("Timestamp skew too large for zapID %s: %.2f", zap_id, abs(now - timestamp / 1000.0))
            return jsonify({"status": "error", "reason": "Timestamp invalid"}), 400

        # === Telemetry Logging ===
        telemetry_log.append({
            "event": event,
            "zapID": zap_id,
            "fingerprint": fingerprint,
            "nonce": nonce,
            "timestamp": timestamp,
            "ip": request.remote_addr,
            "debug": {
                "signature_valid": True,
                "timestamp_valid": True,
                "replay_protected": True,
                "fingerprint_present": True
            },
            "raw_payload": payload,
            "raw_signature": signature_b64,
            "raw_ephemeral": ephemeral_jwk
        })

        logging.debug("Telemetry Log:", telemetry_log)

        # === Determine command response ===
        command = None
        if event == "zapVerify":
            command = "display"
        elif event == "zapLockout":
            with zap_lock:
                if not is_zap_id_locked(zap_id):
                    lock_zap_id(zap_id)
                    logging.warning("zapID locked: %s", zap_id)
                else:
                    logging.info("zapID already locked: %s", zap_id)
            command = "lockUpdate"
        elif event == "zapUnlock":
            with zap_lock:
                if is_zap_id_locked(zap_id):
                    unlock_zap_id(zap_id)
                    logging.info("zapID unlocked: %s", zap_id)
                    command = "lockUpdate"
        elif event == "display":  # Explicitly handle display here
            logging.info("display********")
            log_locked_zapids()
            command = "display"
        elif event == "checkLock":
            command = "lockUpdate"
        else:
            logging.error("No valid command set for event %s", event)
            return jsonify({"status": "error", "reason": "Unknown event"}), 400

        # Ensure `command` is always set before using it
        if command is None:
            logging.error("No valid command set for event %s", event)
            return jsonify({"status": "error", "reason": "Unknown event"}), 400

        command_payload = {"action": command}

        serialized_command = json.dumps(command_payload, separators=(",", ":")).encode("utf-8")
        command_sig = base64.urlsafe_b64encode(
            PRIVATE_KEY.sign(
                serialized_command,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        ).decode("utf-8").rstrip("=")

        logging.info("Responding to zapID %s with action: %s", zap_id, command)

        with zap_lock:
            is_locked = is_zap_id_locked(zap_id)

        return jsonify({
            "payload": command_payload,
            "signature": command_sig,
            "zid": zap_id,
            "locked": is_locked,
            "raw": dict(data)
        }), 200

    except Exception as e:
        logging.exception("ZapCaptcha verification failed")
        return jsonify({"status": "error", "reason": str(e)}), 400
