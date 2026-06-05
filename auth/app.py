import os
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/keyring/api/auth', methods=['POST'])
def auth():
    credential = os.environ.get('KEYRING_CREDENTIAL', '')
    parts = credential.split(':', 1)
    if len(parts) != 2 or not parts[0]:
        return jsonify({'error': 'Server misconfigured'}), 500

    stored_id, stored_pw = parts
    data = request.get_json(silent=True) or {}
    if data.get('id') == stored_id and data.get('password') == stored_pw:
        return jsonify({'ok': True}), 200
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/keyring/api/health')
def health():
    return jsonify({'status': 'ok'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
