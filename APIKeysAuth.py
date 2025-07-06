from flask import Flask, request, jsonify
from functools import wraps
import time

app = Flask(__name__)

API_KEY = "a6ht71"

#decorator to make it use authentication
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("x-api-key")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/public", methods=["GET"])
def public():
    return jsonify({"message": "This is a public endpoint."})



@app.route("/auth-apikey", methods=["GET"])
@require_api_key
def auth_apikey():
    # no sleep—pure auth check
    return "", 204
if __name__ == "__main__":
    app.run(debug=True)
