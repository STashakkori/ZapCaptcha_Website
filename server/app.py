from flask import Flask, request, jsonify, render_template, send_from_directory
import base64
import json
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

logging.basicConfig(filename='/home/stash88/zc/zapdebug.log', level=logging.DEBUG)

telemetry_log = []  # Store captured payloads here

def b64url_decode(data):
    padding = '=' * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/zapcapture', methods=['POST'])
def zapcapture():
    try:
        raw_data = request.get_data(as_text=True)
        logging.debug("Raw POST Body:\n%s", raw_data)
        logging.debug("Headers:\n%s", dict(request.headers))
        logging.debug("Remote IP: %s", request.remote_addr)

        data = request.get_json(force=True)
        payload = data["payload"]
        signature_b64 = data["signature"]
        ephemeral_jwk = data["ephemeral"]

        serialized_payload = json.dumps(payload, separators=(",", ":")).encode()

        e_bytes = b64url_decode(ephemeral_jwk["e"])
        n_bytes = b64url_decode(ephemeral_jwk["n"])

        public_numbers = rsa.RSAPublicNumbers(
            e=int.from_bytes(e_bytes, byteorder="big"),
            n=int.from_bytes(n_bytes, byteorder="big")
        )
        ephemeral_key = public_numbers.public_key(backend=default_backend())

        signature = b64url_decode(signature_b64)
        ephemeral_key.verify(
            signature,
            serialized_payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        log_entry = {
            "event": payload.get("event"),
            "fingerprint": payload.get("fingerprint"),
            "nonce": payload.get("nonce"),
            "timestamp": payload.get("timestamp"),
            "ip": request.remote_addr
        }
        telemetry_log.append(log_entry)

        return jsonify({
            "status": "ok",
            "message": f"✓ Verified {log_entry['event']} from {log_entry['ip']}",
            **log_entry
        }), 200

    except Exception as e:
        logging.exception("ZapCaptcha server verification failed")
        return jsonify({"status": "error", "reason": str(e)}), 400

@app.route('/telemetry')
def show_telemetry():
    return jsonify({
        "telemetry": telemetry_log[-100:]  # Optional cap to last 100 entries
    })
