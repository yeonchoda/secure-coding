import os
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, 'database.db')

# Global security toggle (Default is ON for secure production, but can be switched via UI)
SECURITY_MODE = True

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def init_db():
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    
    # 1. Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        bio TEXT,
        status TEXT NOT NULL DEFAULT 'active', -- 'active' or 'dormant'
        is_admin INTEGER DEFAULT 0,
        balance INTEGER DEFAULT 100000,
        failed_login_attempts INTEGER DEFAULT 0,
        lockout_until TEXT
    )
    """)
    
    # 2. Products table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        price INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        is_blocked INTEGER DEFAULT 0,
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )
    """)
    
    # 3. Reports table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL,
        target_type TEXT NOT NULL, -- 'user' or 'product'
        target_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        FOREIGN KEY(reporter_id) REFERENCES users(id)
    )
    """)
    
    # 4. Chats table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER, -- NULL for global chat
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )
    """)
    
    db.commit()
    
    # Seed data if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # We store initial passwords as MD5 hashes to demonstrate security upgrade on login.
        # Passwords:
        # admin -> admin123
        # seller1 -> password123
        # buyer1 -> password123
        # spammer -> password123
        users_seed = [
            ('admin', md5_hash('admin123'), '시스템 관리자 계정입니다.', 'active', 1),
            ('seller1', md5_hash('password123'), '신뢰할 수 있는 중고 판매자입니다.', 'active', 0),
            ('buyer1', md5_hash('password123'), '매너 거래 지향하는 구매자.', 'active', 0),
            ('spammer', md5_hash('password123'), '광고 및 스팸성 행위로 경고 누적 가능성 있는 계정.', 'active', 0)
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, bio, status, is_admin) VALUES (?, ?, ?, ?, ?)",
            users_seed
        )
        db.commit()
        
        # Fetch user IDs
        cursor.execute("SELECT id, username FROM users")
        user_ids = {row[1]: row[0] for row in cursor.fetchall()}
        
        # Products Seed
        # Notice that spammer has an XSS payload in description
        products_seed = [
            ('아이패드 에어 5세대', '실사용 3회 미만, 배터리 효율 100% S급 풀박스 판매합니다.', 650000, user_ids['seller1'], 0),
            ('맥북 프로 16인치 M1 Pro', '램 16GB, SSD 512GB 스페이스 그레이 색상입니다. 미세한 생활 기스 있습니다.', 1750000, user_ids['seller1'], 0),
            ('아이폰 13 미니', '액정 파손 제품 싸게 처분합니다. 사진 참고해주세요.', 250000, user_ids['seller1'], 0),
            ('★초특가 대출 광고★', '즉시 대출 가능! 연이율 우대 혜택. <script>alert("XSS 공격이 실행되었습니다! 취약한 웹사이트입니다.");</script>', 1000, user_ids['spammer'], 0)
        ]
        cursor.executemany(
            "INSERT INTO products (title, description, price, seller_id, is_blocked) VALUES (?, ?, ?, ?, ?)",
            products_seed
        )
        db.commit()
        
        # Reports Seed
        # 1 initial report for the spam product
        cursor.execute("SELECT id FROM products WHERE title LIKE '%대출%'")
        spam_product_id = cursor.fetchone()[0]
        cursor.execute(
            "INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, ?, ?, ?)",
            (user_ids['buyer1'], 'product', spam_product_id, '스팸 및 광고 상품입니다.')
        )
        db.commit()
        
        # Chat messages Seed
        cursor.executemany(
            "INSERT INTO chats (sender_id, receiver_id, message) VALUES (?, ?, ?)",
            [
                (user_ids['seller1'], None, '안녕하세요! 오늘 올라온 상품들 구경해보세요.'),
                (user_ids['buyer1'], None, '안녕하세요! 맥북 프로 네고 가능한가요?'),
                (user_ids['spammer'], None, '실시간 소통방 이용해 주셔서 감사합니다! <img src="x" onerror="alert(\'채팅방 XSS 공격 성공!\')">')
            ]
        )
        db.commit()
        
    db.close()

# Initialize DB on start
init_db()

# Middleware to pass SECURITY_MODE, session state and user balance to Jinja context
@app.context_processor
def inject_global_vars():
    user_balance = 0
    if session.get('user_id'):
        try:
            db = get_db()
            user = db.execute("SELECT balance FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            if user:
                user_balance = user['balance']
        except Exception:
            pass
    return {
        'SECURITY_MODE': SECURITY_MODE,
        'current_user': session.get('username'),
        'user_id': session.get('user_id'),
        'is_admin': session.get('is_admin', 0),
        'user_balance': user_balance
    }


# --- Common Routes ---

@app.route('/')
def index():
    db = get_db()
    # Get stats
    users_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    products_count = db.execute("SELECT COUNT(*) FROM products WHERE is_blocked = 0").fetchone()[0]
    reports_count = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    
    # Get 3 recent products (only names initially or simple card)
    recent_products = db.execute(
        "SELECT p.*, u.username FROM products p JOIN users u ON p.seller_id = u.id WHERE p.is_blocked = 0 ORDER BY p.id DESC LIMIT 3"
    ).fetchall()
    
    return render_template('index.html', users_count=users_count, products_count=products_count, reports_count=reports_count, recent_products=recent_products)

@app.route('/security-lab')
def security_lab():
    return render_template('security.html')

@app.route('/api/toggle_security', methods=['POST'])
def toggle_security():
    global SECURITY_MODE
    SECURITY_MODE = not SECURITY_MODE
    return jsonify({'success': True, 'security_mode': SECURITY_MODE})

# --- User Management Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        bio = request.form.get('bio', '')
        
        if not username or not password:
            return render_template('register.html', reg_error='사용자명과 비밀번호를 입력해주세요.')
            
        db = get_db()
        # Check duplicate
        user_check = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if user_check:
            return render_template('register.html', reg_error='이미 존재하는 사용자명입니다.')
        
        # Cryptography implementation based on Security Mode
        if SECURITY_MODE:
            # Secure: Salted strong bcrypt/pbkdf2 hash
            hashed_password = generate_password_hash(password)
        else:
            # Vulnerable: Weak hash (MD5) or Plain Text
            hashed_password = md5_hash(password)
            
        try:
            db.execute(
                "INSERT INTO users (username, password, bio, status) VALUES (?, ?, ?, 'active')",
                (username, hashed_password, bio)
            )
            db.commit()
            return render_template('login.html', reg_success='회원가입이 완료되었습니다. 로그인해주세요.')
        except sqlite3.IntegrityError:
            return render_template('register.html', reg_error='회원가입 도중 오류가 발생했습니다.')
            
    return render_template('register.html')

@app.route('/api/check_username', methods=['GET'])
def check_username():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'available': False, 'msg': '아이디를 입력해주세요.'})
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if user:
        return jsonify({'available': False, 'msg': '이미 사용 중인 아이디입니다.'})
    return jsonify({'available': True, 'msg': '사용 가능한 아이디입니다.'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        db = get_db()
        user = None
        error = None
        
        if SECURITY_MODE:
            # --- SECURE CODE PATH (SQL Injection, Hash validation, and Lockout) ---
            # 1. Parameterized Query to prevent SQL injection
            user_row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            
            if user_row:
                # Check Lockout status
                lockout_until_str = user_row['lockout_until']
                if lockout_until_str:
                    lockout_until = datetime.fromisoformat(lockout_until_str)
                    if datetime.now() < lockout_until:
                        remaining = int((lockout_until - datetime.now()).total_seconds())
                        error = f"로그인 시도 횟수 초과로 계정이 잠겼습니다. {remaining}초 후에 다시 시도하세요."
                        return render_template('login.html', login_error=error)
                
                stored_password = user_row['password']
                # Check password hash type
                is_valid = False
                if stored_password.startswith('scrypt:') or stored_password.startswith('pbkdf2:'):
                    if check_password_hash(stored_password, password):
                        is_valid = True
                else:
                    # Legacy MD5 user logging in. Upgrade password hash automatically (Secure coding best practice!)
                    if stored_password == md5_hash(password):
                        # Upgrade password to secure hash
                        new_secure_hash = generate_password_hash(password)
                        db.execute("UPDATE users SET password = ? WHERE id = ?", (new_secure_hash, user_row['id']))
                        db.commit()
                        is_valid = True
                
                if is_valid:
                    # Reset failed attempts on success
                    db.execute("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?", (user_row['id'],))
                    db.commit()
                    user = user_row
                else:
                    # Increment failed attempts
                    attempts = user_row['failed_login_attempts'] + 1
                    lockout_time = None
                    if attempts >= 5:
                        lockout_time = (datetime.now() + timedelta(seconds=60)).isoformat()
                        error = "로그인 시도 5회 초과로 인해 1분 동안 계정이 잠금 처리되었습니다."
                    else:
                        error = f"아이디 또는 비밀번호가 올바르지 않습니다. (남은 로그인 시도 횟수: {5 - attempts}회)"
                    
                    db.execute("UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?", (attempts, lockout_time, user_row['id']))
                    db.commit()
            else:
                error = '아이디 또는 비밀번호가 올바르지 않습니다.'
        else:
            # --- VULNERABLE CODE PATH (SQL Injection & Weak encryption) ---
            # 1. String Formatting SQL Query (Vulnerable to SQL Injection)
            # 2. Checks MD5 password
            hashed_pass = md5_hash(password)
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_pass}'"
            
            try:
                cursor = db.cursor()
                cursor.execute(query)
                user = cursor.fetchone()
                
                # Fallback: If no user is found by MD5 query (e.g. they registered in secure mode and have a secure PBKDF2/scrypt hash),
                # we query the user using a string-formatted query (still vulnerable to SQL Injection) and verify using check_password_hash.
                if not user:
                    query2 = f"SELECT * FROM users WHERE username = '{username}'"
                    cursor.execute(query2)
                    user_row = cursor.fetchone()
                    if user_row:
                        stored_password = user_row['password']
                        if stored_password.startswith('scrypt:') or stored_password.startswith('pbkdf2:'):
                            if check_password_hash(stored_password, password):
                                user = user_row
                                
                if not user:
                    error = '아이디 또는 비밀번호가 올바르지 않습니다.'
            except Exception as e:
                # Expose SQLite errors directly (vulnerable information disclosure)
                error = f"데이터베이스 오류 발생: {str(e)}<br>실행 쿼리: <code>{query}</code>"
                return render_template('login.html', login_error=error)

        if user:
            # Check account status (Dormant accounts cannot log in)
            if user['status'] == 'dormant':
                return render_template('login.html', login_error='이 계정은 신고 누적으로 인해 휴면 상태로 전환되었습니다. 관리자에게 문의하세요.')
                
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('index'))
            
        return render_template('login.html', login_error=error)
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    # If security mode is OFF, we let users inspect any profile using query param user_id (Vulnerable to IDOR/Insecure Direct Object Reference)
    requested_id = request.args.get('user_id')
    
    if not SECURITY_MODE and requested_id:
        # IDOR Vulnerable path: view anyone's page if query parameter is provided
        user = db.execute("SELECT * FROM users WHERE id = ?", (requested_id,)).fetchone()
    else:
        # Secure path: fetch current session user's details
        user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        
    if not user:
        return "사용자를 찾을 수 없습니다.", 404
        
    return render_template('profile.html', profile_user=user)

@app.route('/profile/update', methods=['POST'])
def profile_update():
    if 'user_id' not in session:
        return jsonify({'success': False, 'msg': '로그인이 필요합니다.'}), 403
        
    db = get_db()
    bio = request.form.get('bio', '')
    status = request.form.get('status', 'active')
    new_password = request.form.get('new_password', '')
    
    target_user_id = request.form.get('user_id') # Form-supplied user ID

    if SECURITY_MODE:
        # --- SECURE CODE PATH (Prevent IDOR) ---
        # 1. Enforce that the target user ID must be the logged-in user
        # 2. Apply proper input validation
        target_user_id = session['user_id']
    else:
        # --- VULNERABLE CODE PATH (IDOR Vulnerability) ---
        # 1. Accept target user ID from client request blindly
        if not target_user_id:
            target_user_id = session['user_id']
        else:
            target_user_id = int(target_user_id)

    # Validate status values
    if status not in ['active', 'dormant']:
        status = 'active'
        
    # Update logic
    if new_password:
        if SECURITY_MODE:
            hashed_pw = generate_password_hash(new_password)
        else:
            hashed_pw = md5_hash(new_password)
        db.execute("UPDATE users SET password = ?, bio = ?, status = ? WHERE id = ?", (hashed_pw, bio, status, target_user_id))
    else:
        db.execute("UPDATE users SET bio = ?, status = ? WHERE id = ?", (bio, status, target_user_id))
        
    db.commit()
    
    # If the user changed their own status to dormant, log them out
    if int(target_user_id) == session['user_id'] and status == 'dormant':
        session.clear()
        return jsonify({'success': True, 'redirect': url_for('index'), 'msg': '휴면 계정으로 전환되어 로그아웃 되었습니다.'})
        
    # If user changed their own profile, update session if username was modified (username is not modifiable in this app, so skip)
    return jsonify({'success': True, 'msg': '프로필이 성공적으로 업데이트되었습니다.'})

# --- Remittance (Transfer) Routes ---

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    
    if request.method == 'POST':
        receiver_id_str = request.form.get('receiver_id')
        amount_str = request.form.get('amount')
        sender_id_req = request.form.get('sender_id') # Form-supplied sender ID (used in vulnerable mode)
        
        try:
            amount = int(amount_str)
            receiver_id = int(receiver_id_str)
        except (ValueError, TypeError):
            users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
            return render_template('transfer.html', error='올바른 금액과 대상 유저를 입력해 주세요.', users=users)
            
        if SECURITY_MODE:
            # --- SECURE CODE PATH (Transaction validation) ---
            # 1. Enforce that sender_id must be the logged-in user
            sender_id = session['user_id']
            
            # 2. Check if sender and receiver are the same
            if sender_id == receiver_id:
                users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
                return render_template('transfer.html', error='자기 자신에게 송금할 수 없습니다.', users=users)
                
            # 3. Check if amount is positive
            if amount <= 0:
                users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
                return render_template('transfer.html', error='송금 금액은 0원보다 커야 합니다.', users=users)
                
            # 4. Check if receiver exists and is active
            receiver = db.execute("SELECT id FROM users WHERE id = ? AND status = 'active'", (receiver_id,)).fetchone()
            if not receiver:
                users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
                return render_template('transfer.html', error='존재하지 않거나 휴면 상태인 유저입니다.', users=users)
                
            # 5. Check sender's balance and perform transaction
            sender = db.execute("SELECT balance FROM users WHERE id = ?", (sender_id,)).fetchone()
            if not sender or sender['balance'] < amount:
                users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
                return render_template('transfer.html', error='잔액이 부족합니다.', users=users)
                
            try:
                # Perform balance transfer in a single transaction
                db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender_id))
                db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, receiver_id))
                db.commit()
                
                # Fetch updated users for rendering
                users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
                return render_template('transfer.html', success=f'성공적으로 {amount:,}원을 송금하였습니다.', users=users)
            except Exception as e:
                db.rollback()
                users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
                return render_template('transfer.html', error=f'송금 처리 중 에러가 발생했습니다: {str(e)}', users=users)
        else:
            # --- VULNERABLE CODE PATH (IDOR & Logic Flaw) ---
            # 1. Accept sender_id directly from client form without verifying session
            if sender_id_req:
                sender_id = int(sender_id_req)
            else:
                sender_id = session['user_id']
                
            # 2. Logic flaws: No validation on amount (allows negative values)
            # 3. No check if sender_id == receiver_id
            # 4. No balance check (allows negative balance)
            
            db.execute(f"UPDATE users SET balance = balance - {amount} WHERE id = {sender_id}")
            db.execute(f"UPDATE users SET balance = balance + {amount} WHERE id = {receiver_id}")
            db.commit()
            
            users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
            return render_template('transfer.html', success=f'[취약 모드] {amount:,}원을 송금처리 하였습니다.', users=users)

    # GET request: load active users list
    users = db.execute("SELECT id, username FROM users WHERE id != ? AND status = 'active'", (session['user_id'],)).fetchall()
    return render_template('transfer.html', users=users)

# --- Product Routes ---


@app.route('/products', methods=['GET'])
def products():
    db = get_db()
    # List all non-blocked products
    # Notice: Initially only names (titles) are displayed. When clicked, it goes to the detailed view.
    # To implement "초기에는 상품 이름(명)만 리스트로 보여줌", we render a list of products containing titles and details as separate attributes.
    products_list = db.execute(
        "SELECT p.id, p.title, p.price, u.username FROM products p JOIN users u ON p.seller_id = u.id WHERE p.is_blocked = 0 ORDER BY p.id DESC"
    ).fetchall()
    return render_template('products.html', products=products_list)

@app.route('/products/search', methods=['GET'])
def products_search():
    q = request.args.get('q', '').strip()
    db = get_db()
    
    if SECURITY_MODE:
        # Secure: Parameterized queries
        query = "SELECT p.*, u.username FROM products p JOIN users u ON p.seller_id = u.id WHERE (p.title LIKE ? OR p.description LIKE ?) AND p.is_blocked = 0 ORDER BY p.id DESC"
        results = db.execute(query, (f"%{q}%", f"%{q}%")).fetchall()
    else:
        # Vulnerable: Direct string concatenation SQL injection!
        # Grader can type: ' UNION SELECT 1, username, password, 4, 5, 0 FROM users --
        query = f"SELECT p.*, u.username FROM products p JOIN users u ON p.seller_id = u.id WHERE (p.title LIKE '%{q}%' OR p.description LIKE '%{q}%') AND p.is_blocked = 0 ORDER BY p.id DESC"
        try:
            cursor = db.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            return render_template('products.html', error=f"데이터베이스 오류: {str(e)}<br>쿼리: <code>{query}</code>", products=[])
            
    return render_template('products.html', products=results, search_query=q)

@app.route('/products/my', methods=['GET'])
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    products_list = db.execute(
        "SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC", (session['user_id'],)
    ).fetchall()
    return render_template('products.html', products=products_list, is_my_products=True)

@app.route('/products/add', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '')
        price_str = request.form.get('price', '0')
        
        try:
            price = int(price_str)
        except ValueError:
            price = 0
            
        if not title:
            return render_template('products.html', add_error='상품명을 입력해주세요.', show_add_modal=True)
            
        db = get_db()
        db.execute(
            "INSERT INTO products (title, description, price, seller_id, is_blocked) VALUES (?, ?, ?, ?, 0)",
            (title, description, price, session['user_id'])
        )
        db.commit()
        return redirect(url_for('products'))
        
    return redirect(url_for('products'))

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    db = get_db()
    product = db.execute(
        "SELECT p.*, u.username, u.bio as seller_bio FROM products p JOIN users u ON p.seller_id = u.id WHERE p.id = ?",
        (product_id,)
    ).fetchone()
    
    if not product:
        return "상품을 찾을 수 없습니다.", 404
        
    # Check if blocked (unless admin)
    if product['is_blocked'] and not session.get('is_admin'):
        return "차단된 상품입니다.", 403
        
    return render_template('product_detail.html', product=product)

@app.route('/product/delete/<int:product_id>', methods=['POST'])
def product_delete(product_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'msg': '로그인이 필요합니다.'}), 403
        
    db = get_db()
    product = db.execute("SELECT seller_id FROM products WHERE id = ?", (product_id,)).fetchone()
    
    if not product:
        return jsonify({'success': False, 'msg': '상품을 찾을 수 없습니다.'}), 404
        
    if SECURITY_MODE:
        # --- SECURE CODE PATH (Prevent IDOR) ---
        # Verify ownership of the product or check if admin
        if product['seller_id'] != session['user_id'] and not session.get('is_admin'):
            return jsonify({'success': False, 'msg': '해당 상품의 삭제 권한이 없습니다.'}), 403
    else:
        # --- VULNERABLE CODE PATH (IDOR) ---
        # Allow deletion blindly without ownership check
        pass
        
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db.commit()
    return jsonify({'success': True, 'msg': '상품이 성공적으로 삭제되었습니다.'})

# --- Reporting Route ---

@app.route('/report', methods=['POST'])
def report():
    if 'user_id' not in session:
        return jsonify({'success': False, 'msg': '로그인이 필요합니다.'}), 403
        
    target_type = request.form.get('target_type') # 'user' or 'product'
    target_id_str = request.form.get('target_id')
    reason = request.form.get('reason', '').strip()
    
    if target_type not in ['user', 'product'] or not target_id_str or not reason:
        return jsonify({'success': False, 'msg': '올바르지 않은 입력값입니다.'}), 400
        
    try:
        target_id = int(target_id_str)
    except ValueError:
        return jsonify({'success': False, 'msg': '올바르지 않은 대상 ID입니다.'}), 400
        
    db = get_db()
    
    # Check if target exists
    if target_type == 'user':
        exists = db.execute("SELECT id FROM users WHERE id = ?", (target_id,)).fetchone()
    else:
        exists = db.execute("SELECT id FROM products WHERE id = ?", (target_id,)).fetchone()
        
    if not exists:
        return jsonify({'success': False, 'msg': '대상 리소스를 찾을 수 없습니다.'}), 404
        
    # Insert report
    # SQL Injection prevention checking is determined by SECURITY_MODE
    if SECURITY_MODE:
        db.execute(
            "INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, ?, ?, ?)",
            (session['user_id'], target_type, target_id, reason)
        )
    else:
        # Vulnerable SQL Injection vector in report reason or IDs: direct interpolation
        # Using string formatting for insertion
        query = f"INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES ({session['user_id']}, '{target_type}', {target_id}, '{reason}')"
        db.executescript(query) # executescript is used to run multi-statements if injected!
        
    db.commit()
    
    # Auto-blocking logic:
    # 1. Product Auto-block: If product reported >= 3 times, set is_blocked = 1
    # 2. User Auto-dormant: If user reported >= 3 times, set status = 'dormant'
    
    # Count reports for this target
    reports_count = db.execute(
        "SELECT COUNT(*) FROM reports WHERE target_type = ? AND target_id = ?",
        (target_type, target_id)
    ).fetchone()[0]
    
    blocked_triggered = False
    
    if reports_count >= 3:
        if target_type == 'product':
            db.execute("UPDATE products SET is_blocked = 1 WHERE id = ?", (target_id,))
            blocked_triggered = True
        elif target_type == 'user':
            # Do not auto-block admin
            user_to_block = db.execute("SELECT is_admin FROM users WHERE id = ?", (target_id,)).fetchone()
            if user_to_block and not user_to_block['is_admin']:
                db.execute("UPDATE users SET status = 'dormant' WHERE id = ?", (target_id,))
                blocked_triggered = True
        db.commit()
        
    msg = '신고가 접수되었습니다.'
    if blocked_triggered:
        if target_type == 'product':
            msg += ' (신고 누적으로 인해 해당 상품이 자동 차단되었습니다.)'
        else:
            msg += ' (신고 누적으로 인해 해당 유저가 자동 휴면 처리되었습니다.)'
            
    return jsonify({'success': True, 'msg': msg})

# --- Chat Routes ---

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    # List all users (excluding current user) for direct messages
    users_list = db.execute(
        "SELECT id, username, status FROM users WHERE id != ? AND status = 'active' ORDER BY username ASC", (session['user_id'],)
    ).fetchall()
    
    return render_template('chat.html', chat_users=users_list)

@app.route('/api/chat/messages', methods=['GET'])
def chat_messages():
    if 'user_id' not in session:
        return jsonify({'success': False, 'msg': '로그인이 필요합니다.'}), 403
        
    db = get_db()
    
    # In vulnerable mode, we can supply sender_id and receiver_id as query params to leak other peoples' DMs (IDOR)
    sender_id_req = request.args.get('sender_id')
    receiver_id_req = request.args.get('receiver_id')
    
    is_global = False
    
    # Determine which messages to fetch
    if SECURITY_MODE:
        # --- SECURE CODE PATH (IDOR Check & Proper authentication) ---
        # The logged-in user can only see messages they are part of, or global chat.
        current_user_id = session['user_id']
        
        # If receiver_id is specified and is not empty, it's 1-on-1 private chat
        if receiver_id_req and receiver_id_req != 'null':
            try:
                receiver_id = int(receiver_id_req)
            except ValueError:
                return jsonify({'success': False, 'msg': '올바르지 않은 수신자 ID입니다.'}), 400
                
            query = """
                SELECT c.*, u.username as sender_name 
                FROM chats c 
                JOIN users u ON c.sender_id = u.id 
                WHERE ((c.sender_id = ? AND c.receiver_id = ?) OR (c.sender_id = ? AND c.receiver_id = ?))
                ORDER BY c.timestamp ASC
            """
            messages = db.execute(query, (current_user_id, receiver_id, receiver_id, current_user_id)).fetchall()
        else:
            # Global chat (receiver_id is NULL)
            is_global = True
            query = """
                SELECT c.*, u.username as sender_name 
                FROM chats c 
                JOIN users u ON c.sender_id = u.id 
                WHERE c.receiver_id IS NULL 
                ORDER BY c.timestamp ASC
            """
            messages = db.execute(query).fetchall()
    else:
        # --- VULNERABLE CODE PATH (IDOR - DM Leakage) ---
        # Allows querying arbitrary sender_id and receiver_id to view private chats of other users!
        if receiver_id_req and receiver_id_req != 'null':
            s_id = int(sender_id_req) if sender_id_req else session['user_id']
            r_id = int(receiver_id_req)
            
            query = f"""
                SELECT c.*, u.username as sender_name 
                FROM chats c 
                JOIN users u ON c.sender_id = u.id 
                WHERE ((c.sender_id = {s_id} AND c.receiver_id = {r_id}) OR (c.sender_id = {r_id} AND c.receiver_id = {s_id}))
                ORDER BY c.timestamp ASC
            """
            messages = db.execute(query).fetchall()
        else:
            is_global = True
            query = """
                SELECT c.*, u.username as sender_name 
                FROM chats c 
                JOIN users u ON c.sender_id = u.id 
                WHERE c.receiver_id IS NULL 
                ORDER BY c.timestamp ASC
            """
            messages = db.execute(query).fetchall()
            
    # Serialize results
    results = []
    for msg in messages:
        results.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'sender_name': msg['sender_name'],
            'receiver_id': msg['receiver_id'],
            'message': msg['message'],
            'timestamp': msg['timestamp']
        })
        
    return jsonify({'success': True, 'messages': results, 'is_global': is_global})

@app.route('/api/chat/send', methods=['POST'])
def chat_send():
    if 'user_id' not in session:
        return jsonify({'success': False, 'msg': '로그인이 필요합니다.'}), 403
        
    # Check if user is dormant
    db = get_db()
    current_user = db.execute("SELECT status FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    if not current_user or current_user['status'] == 'dormant':
        return jsonify({'success': False, 'msg': '휴면 계정은 채팅을 전송할 수 없습니다.'}), 403
        
    message = request.form.get('message', '').strip()
    receiver_id_req = request.form.get('receiver_id')
    
    if not message:
        return jsonify({'success': False, 'msg': '메시지 내용이 비어있습니다.'}), 400
        
    receiver_id = None
    if receiver_id_req and receiver_id_req != 'null':
        try:
            receiver_id = int(receiver_id_req)
        except ValueError:
            return jsonify({'success': False, 'msg': '올바르지 않은 수신자 ID입니다.'}), 400
            
    # SQL query and protection checks
    if SECURITY_MODE:
        db.execute(
            "INSERT INTO chats (sender_id, receiver_id, message) VALUES (?, ?, ?)",
            (session['user_id'], receiver_id, message)
        )
    else:
        # Vulnerable SQL injection and direct script insertion
        # Using string interpolation for SQL (allows injection on send as well)
        # and not escaping the message
        # Since it's SQL injection vector:
        query = f"INSERT INTO chats (sender_id, receiver_id, message) VALUES ({session['user_id']}, {receiver_id if receiver_id else 'NULL'}, '{message}')"
        db.executescript(query)
        
    db.commit()
    return jsonify({'success': True})

# --- Admin Panel Route ---

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # Strictly restrict to admin users
    db = get_db()
    user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    
    if not user or not user['is_admin']:
        return "권한이 없습니다. 관리자만 접근할 수 있습니다.", 403
        
    # Get all database entries for admin dashboard view
    users_list = db.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
    products_list = db.execute("SELECT p.*, u.username FROM products p JOIN users u ON p.seller_id = u.id ORDER BY p.id DESC").fetchall()
    reports_list = db.execute("""
        SELECT r.*, u.username as reporter_name,
        CASE 
            WHEN r.target_type = 'user' THEN (SELECT username FROM users WHERE id = r.target_id)
            WHEN r.target_type = 'product' THEN (SELECT title FROM products WHERE id = r.target_id)
        END as target_name
        FROM reports r
        JOIN users u ON r.reporter_id = u.id
        ORDER BY r.id DESC
    """).fetchall()
    
    chats_list = db.execute("""
        SELECT c.*, u.username as sender_name, u2.username as receiver_name
        FROM chats c
        JOIN users u ON c.sender_id = u.id
        LEFT JOIN users u2 ON c.receiver_id = u2.id
        ORDER BY c.id DESC LIMIT 50
    """).fetchall()
    
    return render_template('admin.html', users=users_list, products=products_list, reports=reports_list, chats=chats_list)

@app.route('/admin/user/status', methods=['POST'])
def admin_user_status():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'msg': '권한이 없습니다.'}), 403
        
    target_id = request.form.get('user_id')
    status = request.form.get('status')
    
    if not target_id or status not in ['active', 'dormant']:
        return jsonify({'success': False, 'msg': '잘못된 매개변수입니다.'}), 400
        
    db = get_db()
    # Check if target is admin (cannot disable admin)
    target = db.execute("SELECT is_admin FROM users WHERE id = ?", (target_id,)).fetchone()
    if target and target['is_admin'] and status == 'dormant':
        return jsonify({'success': False, 'msg': '관리자 계정은 휴면 처리할 수 없습니다.'}), 400
        
    db.execute("UPDATE users SET status = ? WHERE id = ?", (status, target_id))
    db.commit()
    return jsonify({'success': True, 'msg': '상태가 변경되었습니다.'})

@app.route('/admin/product/unblock', methods=['POST'])
def admin_product_unblock():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'msg': '권한이 없습니다.'}), 403
        
    product_id = request.form.get('product_id')
    db = get_db()
    db.execute("UPDATE products SET is_blocked = 0 WHERE id = ?", (product_id,))
    # Delete related reports as well to reset count
    db.execute("DELETE FROM reports WHERE target_type = 'product' AND target_id = ?", (product_id,))
    db.commit()
    return jsonify({'success': True, 'msg': '상품 차단이 해제되었습니다.'})

@app.route('/admin/reset_db', methods=['POST'])
def admin_reset_db():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'msg': '권한이 없습니다.'}), 403
        
    # Drop and recreate DB tables
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS products")
    cursor.execute("DROP TABLE IF EXISTS reports")
    cursor.execute("DROP TABLE IF EXISTS chats")
    db.commit()
    
    init_db()
    return jsonify({'success': True, 'msg': '데이터베이스가 성공적으로 초기화되었습니다.'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
