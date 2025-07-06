# app.py
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector, current_token
from authlib.oauth2.rfc6749 import grants
# from authlib.oauth2.rfc6749.tokens import BearerToken
from werkzeug.security import gen_salt, check_password_hash, generate_password_hash


class User:
    def __init__(self, username, password):
        self.username = username
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Client:
    def __init__(self, client_id, client_secret, grant_types, redirect_uris):
        self.client_id = client_id
        self.client_secret = client_secret
        self.grant_types = grant_types
        self.redirect_uris = redirect_uris
        self.token_endpoint_auth_method = 'client_secret_post'

    def check_client_secret(self, secret):
        return self.client_secret == secret

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types
    
    def check_endpoint_auth_method(self, method, endpoint):
        return endpoint == 'token' and method == self.token_endpoint_auth_method

_tokens = {}

_users = {
    'alice': User('alice', 'wonderland'),
}
_clients = {}

def save_token(token_data, request):
    # token_data includes access_token, refresh_token, expires_in, scope, etc.
    _tokens[token_data['access_token']] = {
        'client_id': request.client.client_id,
        'user': request.user.username,
        'expires_at': datetime.utcnow() + timedelta(seconds=token_data['expires_in'])
    }

app = Flask(__name__)
app.config['OAUTH2_REFRESH_TOKEN_GENERATOR'] = True

authorization = AuthorizationServer(app, query_client=lambda cid: _clients.get(cid),
                                    save_token=save_token)
require_oauth = ResourceProtector()

# --- Grant class ---
class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_post']

    def authenticate_user(self, username, password):
        user = _users.get(username)
        if user and user.check_password(password):
            return user

authorization.register_grant(PasswordGrant)

# bearer token validator
class BearerTokenValidator:
    realm = "api"
    TOKEN_TYPE = "Bearer"

    def __call__(self, token_string):
        data = _tokens.get(token_string)
        if not data:
            return None
        # check expiry
        if datetime.utcnow() > data['expires_at']:
            _tokens.pop(token_string)
            return None
        # create a dummy token object
        class Token:
            user = _users[data['user']]
            client_id = data['client_id']
        return Token()

require_oauth.register_token_validator(BearerTokenValidator())

@app.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()

@app.route('/api/profile')
@require_oauth()
def api_profile():
    user = current_token.user
    return jsonify({
        'username': user.username,
        'message': f'Hello, {user.username}! This is your profile.'
    })

@app.route('/init')
def init_data():
    client_id = gen_salt(24)
    client_secret = gen_salt(48)
    _clients[client_id] = Client(
        client_id=client_id,
        client_secret=client_secret,
        grant_types=['password'],
        redirect_uris=[]
    )
    return jsonify({
        'client_id': client_id,
        'client_secret': client_secret,
        'note': 'Use grant_type=password to get tokens'
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
