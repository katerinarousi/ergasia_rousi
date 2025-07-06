#!/bin/bash

set -e

USERS=1000
SPAWN_RATE=100
RUN_TIME="2m"
RESULTS_DIR="results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo
echo "=== Running Locust for APIKeyUser ==="
export LOCUST_USER_CLASSES="APIKeyUser"
export API_KEY="a6ht71"
export APIKEY_HOST="http://localhost:5001"
locust -f locustfile.py --headless --users $USERS --spawn-rate $SPAWN_RATE --run-time $RUN_TIME \
  --host "$APIKEY_HOST" \
  --csv="$RESULTS_DIR/apikey" > "$RESULTS_DIR/apikey.log" 2>&1
unset LOCUST_USER_CLASSES API_KEY APIKEY_HOST

echo
echo "=== Running Locust for JWTUser ==="
export LOCUST_USER_CLASSES="JWTUser"
export JWT_USERNAME="katerina"
export JWT_PASSWORD="1234"
export JWT_HOST="http://localhost:5002"
export JWT_LOGIN_PATH="/login-rs"
export JWT_PROTECTED_PATH="/auth-jwt-rs256"
export JWT_TOKEN_FIELD="token"
locust -f locustfile.py --headless --users $USERS --spawn-rate $SPAWN_RATE --run-time $RUN_TIME \
  --host "$JWT_HOST" \
  --csv="$RESULTS_DIR/jwt" > "$RESULTS_DIR/jwt.log" 2>&1
unset LOCUST_USER_CLASSES JWT_USERNAME JWT_PASSWORD JWT_HOST JWT_LOGIN_PATH JWT_PROTECTED_PATH JWT_TOKEN_FIELD


echo
echo "=== Registering OAuth client and Running Locust for OAuthUser ==="
export LOCUST_USER_CLASSES="OAuthUser"
CREDS=$(curl -s http://localhost:5003/init)
echo "CREDS raw: $CREDS"
export CLIENT_ID=$(echo "$CREDS" | jq -r .client_id)
export CLIENT_SECRET=$(echo "$CREDS" | jq -r .client_secret)
export OAUTH_USERNAME="alice"
export OAUTH_PASSWORD="wonderland"
export OAUTH_HOST="http://localhost:5003"
export OAUTH_TOKEN_PATH="/oauth/token"
export OAUTH_PROFILE_PATH="/api/profile"
echo "Using CLIENT_ID=$CLIENT_ID"
echo "Using CLIENT_SECRET=$CLIENT_SECRET"

locust -f locustfile.py --headless --users $USERS --spawn-rate $SPAWN_RATE --run-time $RUN_TIME \
  --host "$OAUTH_HOST" \
  --csv="$RESULTS_DIR/oauth" > "$RESULTS_DIR/oauth.log" 2>&1
unset LOCUST_USER_CLASSES CLIENT_ID CLIENT_SECRET OAUTH_USERNAME OAUTH_PASSWORD OAUTH_HOST OAUTH_TOKEN_PATH OAUTH_PROFILE_PATH

echo