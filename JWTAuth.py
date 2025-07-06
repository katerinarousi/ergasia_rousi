from flask import Flask, request, jsonify
from functools import wraps
import jwt
import time
import datetime

app = Flask(__name__)

with open("private.pem", "rb") as f:
    RS256_PRIVATE = f.read()
with open("public.pem", "rb") as f:
    RS256_PUBLIC = f.read()

def require_rsjwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth.split(" ", 1)[1]
        try:
            jwt.decode(token, RS256_PUBLIC, algorithms=["RS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"error": str(e)}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/login-rs", methods=["POST"])
def login_rs():
    creds = request.get_json() or {}
    if creds.get("username") == "katerina" and creds.get("password") == "1234":
        payload = {
            "user": creds["username"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, RS256_PRIVATE, algorithm="RS256")
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/auth-jwt-rs256", methods=["GET"])
@require_rsjwt
def auth_jwt_rs256():
    return "", 204

if __name__ == "__main__":
    # app.run(debug=True)
    app.run(debug=True, port=5001)

