# 
import os
from locust import HttpUser, task, between

class APIKeyUser(HttpUser):
    host = os.getenv("APIKEY_HOST", "http://localhost:5001")
    wait_time = between(1, 3)

    def on_start(self):
        api_key = os.getenv("API_KEY", "1234")
        self.api_key_headers = {"X-API-KEY": api_key}

    @task
    def auth_apikey(self):
        self.client.get(
            "/auth-apikey",
            headers=self.api_key_headers,
            name="APIKey /auth-apikey"
        )

class JWTUser(HttpUser):
    host = os.getenv("JWT_HOST", "http://localhost:5002")
    wait_time = between(1, 3)

    def on_start(self):
        self.jwt_headers = {}
        username = os.getenv("JWT_USERNAME", "katerina")
        password = os.getenv("JWT_PASSWORD", "1234")
        login_endpoint = os.getenv("JWT_LOGIN_PATH", "/login-rs")
        token_field = os.getenv("JWT_TOKEN_FIELD", "token")
        resp = self.client.post(
            login_endpoint,
            json={"username": username, "password": password},
            name="POST /login-rs"
        )
        if resp.status_code == 200:
            token = resp.json().get(token_field)
            if token:
                self.jwt_headers = {"Authorization": f"Bearer {token}"}

    @task
    def auth_jwt(self):
        if not self.jwt_headers:
            return
        protected_path = os.getenv("JWT_PROTECTED_PATH", "/auth-jwt-rs256")
        self.client.get(
            protected_path,
            headers=self.jwt_headers,
            name="JWT /auth-jwt-rs256"
        )

class OAuthUser(HttpUser):
    host = os.getenv("OAUTH_HOST", "http://localhost:5003")
    wait_time = between(1, 3)

    def on_start(self):
        self.oauth_headers = {}
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        username = os.getenv("OAUTH_USERNAME", "alice")
        password = os.getenv("OAUTH_PASSWORD", "wonderland")
        token_path = os.getenv("OAUTH_TOKEN_PATH", "/oauth/token")
        resp = self.client.post(
            token_path,
            data={
                "grant_type": "password",
                "username": username,
                "password": password,
                "client_id": client_id,
                "client_secret": client_secret
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            name="OAuth POST /oauth/token"
        )
        if resp.status_code == 200:
            tok = resp.json().get("access_token")
            if tok:
                self.oauth_headers = {"Authorization": f"Bearer {tok}"}
        else:
            print(">>> OAuth token fetch failed:", resp.status_code, resp.text)

    @task
    def auth_oauth(self):
        if not self.oauth_headers:
            return
        profile_path = os.getenv("OAUTH_PROFILE_PATH", "/api/profile")
        self.client.get(
            profile_path,
            headers=self.oauth_headers,
            name="OAuth GET /api/profile"
        )
