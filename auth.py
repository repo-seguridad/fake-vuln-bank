from flask import jsonify, request
import jwt
import datetime
import os
import secrets
import sqlite3
from functools import wraps

# Fix (M1-R02, M1-R09): secret is loaded from the environment and never
# hardcoded. If it is missing a strong random one is generated at startup.
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(64)

# Fix (M1-R02): only a safe signing algorithm is allowed; 'none' is rejected.
ALGORITHMS = ['HS256']

# Token lifetime (minutes) so sessions expire (CWE-613).
TOKEN_TTL_MINUTES = int(os.environ.get("JWT_TTL_MINUTES", "60"))

def generate_token(user_id, username, is_admin=False):
    """
    Generate a signed JWT token.
    Fix (M1-R02, M1-R08): the token carries an expiration (exp), issued-at
    (iat) and a unique id (jti), and is signed with the environment secret.
    """
    now = datetime.datetime.utcnow()
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        'iat': now,
        'exp': now + datetime.timedelta(minutes=TOKEN_TTL_MINUTES),
        'jti': secrets.token_hex(16),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

def verify_token(token):
    """
    Verify a JWT token.
    Fix (M1-R02): the signature and expiration are always verified, only
    HS256 is accepted, and there is no unsigned fallback. Any invalid or
    expired token is rejected (returns None).
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=ALGORITHMS,
            options={'require': ['exp', 'iat']},
        )
        return payload
    except jwt.PyJWTError:
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Try to get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Handle 'Bearer' token format
                if 'Bearer' in auth_header:
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
            except IndexError:
                token = None
                
        # Vulnerability: Multiple token locations (token hijacking risk)
        # Also check query parameters (vulnerable by design)
        if not token and 'token' in request.args:
            token = request.args['token']
            
        # Also check form data (vulnerable by design)
        if not token and 'token' in request.form:
            token = request.form['token']
            
        # Also check cookies (vulnerable by design)
        if not token and 'token' in request.cookies:
            token = request.cookies['token']
            
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            current_user = verify_token(token)
            if current_user is None:
                return jsonify({'error': 'Invalid token'}), 401
                
            # Vulnerability: No token expiration check
            return f(current_user, *args, **kwargs)
            
        except Exception as e:
            # Vulnerability: Detailed error exposure
            return jsonify({
                'error': 'Invalid token', 
                'details': str(e)
            }), 401
            
    return decorated

# New API endpoints with JWT authentication
def init_auth_routes(app):
    @app.route('/api/login', methods=['POST'])
    def api_login():
        auth = request.get_json()
        suspension_message = 'Your account has been suspended, contact support or walk in to any of our branch to resolve the issue'
        
        if not auth or not auth.get('username') or not auth.get('password'):
            return jsonify({'error': 'Missing credentials'}), 401
            
        # Fix (M1-R01): parameterized query prevents SQL injection (SQLite uses ? placeholders)
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        c.execute(query, (auth.get('username'), auth.get('password')))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        if len(user) > 9 and user[9]:
            return jsonify({'error': suspension_message}), 403
            
        # Generate token
        token = generate_token(user[0], user[1], user[5])
        
        # Vulnerability: Exposed sensitive data in response
        return jsonify({
            'token': token,
            'user_id': user[0],
            'username': user[1],
            'account_number': user[3],
            'is_admin': user[5],
            'debug_info': {
                'login_time': str(datetime.datetime.now()),
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
        })

    @app.route('/api/check_balance', methods=['GET'])
    @token_required
    def api_check_balance(current_user):
        # Vulnerability: No additional authorization check
        # Any valid token can check any account balance
        account_number = request.args.get('account_number')
        
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        c.execute(f"SELECT username, balance FROM users WHERE account_number='{account_number}'")
        user = c.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                'username': user[0],
                'balance': user[1],
                'checked_by': current_user['username']
            })
        return jsonify({'error': 'Account not found'}), 404

    @app.route('/api/transfer', methods=['POST'])
    @token_required
    def api_transfer(current_user):
        data = request.get_json()
        
        if not data or not data.get('to_account') or not data.get('amount'):
            return jsonify({'error': 'Missing transfer details'}), 400
            
        # Vulnerability: No amount validation
        amount = float(data.get('amount'))
        to_account = data.get('to_account')
        
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        
        # Vulnerability: Race condition in transfer
        c.execute(f"SELECT balance FROM users WHERE id={current_user['user_id']}")
        balance = c.fetchone()[0]
        
        if balance >= amount:
            # Vulnerability: SQL injection possible in to_account
            c.execute(f"UPDATE users SET balance = balance - {amount} WHERE id={current_user['user_id']}")
            c.execute(f"UPDATE users SET balance = balance + {amount} WHERE account_number='{to_account}'")
            conn.commit()
            
            # Vulnerability: Information disclosure
            c.execute(f"SELECT username, balance FROM users WHERE account_number='{to_account}'")
            recipient = c.fetchone()
            
            conn.close()
            return jsonify({
                'status': 'success',
                'new_balance': balance - amount,
                'recipient': recipient[0],
                'recipient_new_balance': recipient[1]
            })
            
        conn.close()
        return jsonify({'error': 'Insufficient funds'}), 400
