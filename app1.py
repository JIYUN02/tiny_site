import sqlite3
import uuid
import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import bleach
from datetime import timedelta
from werkzeug.utils import secure_filename
from functools import wraps


app = Flask(__name__)
# 안전한 랜덤 시크릿 키 생성
app.config['SECRET_KEY'] = os.urandom(24)
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)  # CSRF 보호 활성화

# 관리자 계정 생성 함수 (처음 실행시 호출)
def create_admin_account():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # 관리자 계정 확인
        cursor.execute("SELECT * FROM user WHERE role = 'admin'")
        admin = cursor.fetchone()
        
        # 관리자 계정이 없으면 생성
        if not admin:
            admin_id = str(uuid.uuid4())
            admin_username = "admin"
            admin_password = generate_password_hash("Admin@123")  # 기본 비밀번호, 보안을 위해 변경 필요
            
            cursor.execute(
                "INSERT INTO user (id, username, password, role) VALUES (?, ?, ?, ?)",
                (admin_id, admin_username, admin_password, 'admin')
            )
            db.commit()
            print("관리자 계정이 생성되었습니다.")

# 파일 업로드 설정
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 최대 16MB 파일

# 업로드 폴더가 없으면 생성
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 파일 확장자 확인 함수
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                role TEXT DEFAULT 'user',
                report_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            )
        """)
        # product 테이블에 is_sold 컬럼 추가 (init_db 함수 수정)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                image_path TEXT,
                report_count INTEGER DEFAULT 0,
                is_sold INTEGER DEFAULT 0
            )
        """)  
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 페이(지갑) 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wallet (
                user_id TEXT PRIMARY KEY,
                balance REAL DEFAULT 0.0,
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        """)
        
        # 송금 내역 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS "transaction" (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount REAL NOT NULL,
                message TEXT,
                status TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES user(id),
                FOREIGN KEY (receiver_id) REFERENCES user(id)
            )
        """)
        
        # 1:1 채팅 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES user(id),
                FOREIGN KEY (receiver_id) REFERENCES user(id)
            )
        """)

        db.commit()

# 입력 검증 함수들
def validate_username(username):
    if not username or not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False
    return True

def validate_password(password):
    # 최소 8자, 하나 이상의 특수문자 포함
    if not password or len(password) < 8:
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def validate_price(price):
    if not price or not re.match(r'^\d+(\.\d{1,2})?$', price):
        return False
    return True

def sanitize_input(text):
    if text:
        return bleach.clean(text)
    return text

# 판매완료 처리 라우트 추가
@app.route('/product/mark_sold/<product_id>', methods=['POST'])
def mark_product_sold(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET is_sold = 1 WHERE id = ? AND seller_id = ?", 
                  (product_id, session['user_id']))
    db.commit()
    flash('상품이 판매완료 처리되었습니다.')
    return redirect(url_for('view_product', product_id=product_id))

# 관리자 확인 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT role FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# 홈 화면 수정
@app.route('/')
def index():
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        # 모든 상품 조회
        cursor.execute("""
            SELECT p.*, u.username as seller_name 
            FROM product p
            JOIN user u ON p.seller_id = u.id
            ORDER BY p.rowid DESC
        """)
        all_products = cursor.fetchall()
        return render_template('home.html', products=all_products)
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 입력 검증
        if not validate_username(username):
            flash('사용자명은 3-20자의 영문, 숫자, 언더스코어만 사용할 수 있습니다.')
            return redirect(url_for('register'))
            
        if not validate_password(password):
            flash('비밀번호는 최소 8자 이상이며, 특수문자를 하나 이상 포함해야 합니다.')
            return redirect(url_for('register'))
            
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
            
        user_id = str(uuid.uuid4())
        # 비밀번호 해싱
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        
        # 새 사용자의 지갑 생성
        cursor.execute("INSERT INTO wallet (user_id, balance) VALUES (?, 0.0)", (user_id,))
        db.commit()
        
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('아이디와 비밀번호를 모두 입력해주세요.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        # 비밀번호 검증
        if user and check_password_hash(user['password'], password) and user['is_active'] == 1:
            session['user_id'] = user['id']
            session['username'] = user['username'] 
            session['role'] = user['role']
            
            app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
            session.permanent = True  # 세션 지속성 설정
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        elif user and user['is_active'] == 0:
            flash('계정이 비활성화되었습니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.clear()  # 모든 세션 데이터 제거
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드 수정
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 사용자의 상품만 조회
    cursor.execute("SELECT * FROM product WHERE seller_id = ? ORDER BY rowid DESC", (session['user_id'],))
    user_products = cursor.fetchall()

    # 채팅 목록 (최근 대화 상대)
    try:    
        cursor.execute("""
            SELECT DISTINCT 
                CASE 
                    WHEN pm.sender_id = ? THEN pm.receiver_id 
                    ELSE pm.sender_id 
                END as chat_partner_id,
                u.username as chat_partner_name,
                MAX(pm.timestamp) as last_message_time
            FROM private_message pm
            JOIN user u ON (
                (pm.sender_id = ? AND pm.receiver_id = u.id) OR 
                (pm.receiver_id = ? AND pm.sender_id = u.id)
            )
            WHERE pm.sender_id = ? OR pm.receiver_id = ?
            GROUP BY chat_partner_id
            ORDER BY last_message_time DESC
            LIMIT 5
        """, (session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id']))
        recent_chats = cursor.fetchall()
    except:
        recent_chats=[]

    # 읽지 않은 메시지 수
    try:
        cursor.execute("""
            SELECT COUNT(*) as unread_count 
            FROM private_message 
            WHERE receiver_id = ? AND is_read = 0
        """, (session['user_id'],))
        unread_messages = cursor.fetchone()['unread_count']
    except:
        unread_messages=0
    return render_template('dashboard.html', 
                          products=user_products, 
                          user=current_user, 
                          recent_chats=recent_chats,
                          unread_messages=unread_messages)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        # XSS 방지를 위한 입력 정제
        bio = sanitize_input(request.form.get('bio', ''))
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
        
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 사용자의 상품 목록
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    user_products = cursor.fetchall()
    
    return render_template('profile.html', user=current_user, products=user_products)

@app.route('/mypage', methods=['GET', 'POST'])
def mypage():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        bio = sanitize_input(request.form.get('bio', ''))
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        # 비밀번호 변경 요청이 있는 경우
        if current_password and new_password:
            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            
            if not check_password_hash(user['password'], current_password):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('mypage'))
                
            if not validate_password(new_password):
                flash('새 비밀번호는 최소 8자 이상이며, 특수문자를 하나 이상 포함해야 합니다.')
                return redirect(url_for('mypage'))
                
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", 
                         (hashed_password, session['user_id']))
            flash('비밀번호가 변경되었습니다.')
        
        # 소개글 업데이트
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('mypage'))
        
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 사용자의 상품 목록
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    user_products = cursor.fetchall()
    
    return render_template('mypage.html', user=current_user, products=user_products)

@app.route('/user/<user_id>')
def view_user(user_id):
    if not user_id or not re.match(r'^[a-f0-9-]{36}$', user_id):
        flash('유효하지 않은 사용자 ID입니다.')
        return redirect(url_for('dashboard'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("SELECT id, username, bio FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 사용자의 상품 목록
    cursor.execute("SELECT * FROM product WHERE seller_id = ? AND is_sold = 0", (user_id,))
    user_products = cursor.fetchall()
    
    return render_template('view_user.html', user=user, products=user_products)

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    if not product_id or not re.match(r'^[a-f0-9-]{36}$', product_id):
        flash('유효하지 않은 상품 ID입니다.')
        return redirect(url_for('dashboard'))
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT id, username, bio FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    # 현재 사용자가 판매자인지 확인
    is_seller = 'user_id' in session and session['user_id'] == product['seller_id']
    
    return render_template('view_product.html', 
                         product=product, 
                         seller=seller, 
                         is_seller=is_seller)

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    # XSS 방지를 위한 메시지 정제
    if 'message' in data:
        data['message'] = sanitize_input(data['message'])
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 페이 관련 라우트
@app.route('/wallet')
def wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 지갑 정보 조회 또는 생성
        cursor.execute("SELECT * FROM wallet WHERE user_id = ?", (session['user_id'],))
        wallet = cursor.fetchone()
        if not wallet:
            cursor.execute("INSERT INTO wallet (user_id, balance) VALUES (?, 0.0)", (session['user_id'],))
            db.commit()
            wallet = {'user_id': session['user_id'], 'balance': 0.0}
        
        # 송금 내역 조회
        cursor.execute("""
            SELECT t.*, u1.username as sender_name, u2.username as receiver_name 
            FROM "transaction" t
            JOIN user u1 ON t.sender_id = u1.id
            JOIN user u2 ON t.receiver_id = u2.id
            WHERE t.sender_id = ? OR t.receiver_id = ?
            ORDER BY t.timestamp DESC
        """, (session['user_id'], session['user_id']))
        transactions = cursor.fetchall()
        
        return render_template('wallet.html', wallet=wallet, transactions=transactions)
    except Exception as e:
        flash(f'지갑 정보를 불러오는 중 오류가 발생했습니다: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/wallet/charge', methods=['POST'])
def charge_wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = request.form.get('amount', type=float)
    if not amount or amount <= 0:
        flash('유효한 금액을 입력해주세요.')
        return redirect(url_for('wallet'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE wallet SET balance = balance + ? WHERE user_id = ?", (amount, session['user_id']))
    db.commit()
    
    flash(f'{amount}원이 충전되었습니다.')
    return redirect(url_for('wallet'))

@app.route('/send_money', methods=['GET', 'POST'])
def send_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        receiver_username = request.form.get('receiver_username')
        amount = request.form.get('amount', type=float)
        message = sanitize_input(request.form.get('message', ''))
        password = request.form.get('password')
        
        if not receiver_username or not amount or not password:
            flash('모든 필수 항목을 입력해주세요.')
            return redirect(url_for('send_money'))
        
        if amount <= 0:
            flash('0보다 큰 금액을 입력해주세요.')
            return redirect(url_for('send_money'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 비밀번호 확인
        cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not user or not check_password_hash(user['password'], password):
            flash('비밀번호가 올바르지 않습니다.')
            return redirect(url_for('send_money'))
        
        # 수신자 확인
        cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('send_money'))
        
        # 자기 자신에게 송금 불가
        if receiver['id'] == session['user_id']:
            flash('자기 자신에게 송금할 수 없습니다.')
            return redirect(url_for('send_money'))
        
        # 잔액 확인
        cursor.execute("SELECT balance FROM wallet WHERE user_id = ?", (session['user_id'],))
        wallet = cursor.fetchone()
        if not wallet or wallet['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('wallet'))
        
        # 트랜잭션 시작
        try:
            cursor.execute("BEGIN TRANSACTION")
            
            # 송신자 잔액 감소
            cursor.execute("UPDATE wallet SET balance = balance - ? WHERE user_id = ?", (amount, session['user_id']))
            
            # 수신자 잔액 증가 (존재하지 않으면 지갑 생성)
            cursor.execute("INSERT OR IGNORE INTO wallet (user_id, balance) VALUES (?, 0)", (receiver['id'],))
            cursor.execute("UPDATE wallet SET balance = balance + ? WHERE user_id = ?", (amount, receiver['id']))
            
            # 송금 내역 저장
            transaction_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO \"transaction\" (id, sender_id, receiver_id, amount, message, status) VALUES (?, ?, ?, ?, ?, ?)",
                (transaction_id, session['user_id'], receiver['id'], amount, message, 'completed')
            )
            
            cursor.execute("COMMIT")
            flash('송금이 완료되었습니다.')
            return redirect(url_for('wallet'))
            
        except Exception as e:
            cursor.execute("ROLLBACK")
            flash('송금 중 오류가 발생했습니다.')
            return redirect(url_for('wallet'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT balance FROM wallet WHERE user_id = ?", (session['user_id'],))
    wallet = cursor.fetchone()
    balance = wallet['balance'] if wallet else 0
    
    return render_template('send_money.html', balance=balance)

@app.route('/request_money', methods=['GET', 'POST'])
def request_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        receiver_username = request.form.get('receiver_username')
        amount = request.form.get('amount', type=float)
        message = sanitize_input(request.form.get('message', ''))
        
        if not receiver_username or not amount:
            flash('모든 필수 항목을 입력해주세요.')
            return redirect(url_for('request_money'))
        
        if amount <= 0:
            flash('0보다 큰 금액을 입력해주세요.')
            return redirect(url_for('request_money'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 수신자 확인
        cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('request_money'))
        
        # 자기 자신에게 요청 불가
        if receiver['id'] == session['user_id']:
            flash('자기 자신에게 송금 요청할 수 없습니다.')
            return redirect(url_for('request_money'))
        
        # 송금 요청 내역 저장
        transaction_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO \"transaction\" (id, sender_id, receiver_id, amount, message, status) VALUES (?, ?, ?, ?, ?, ?)",
            (transaction_id, receiver['id'], session['user_id'], amount, message, 'requested')
        )
        db.commit()
        
        # 요청 알림을 개인 메시지로 보내기
        message_id = str(uuid.uuid4())
        request_message = f"[송금 요청] {amount}원을 요청했습니다. 메시지: {message}"
        cursor.execute(
            "INSERT INTO private_message (id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)",
            (message_id, session['user_id'], receiver['id'], request_message)
        )
        db.commit()
        
        flash('송금 요청이 전송되었습니다.')
        return redirect(url_for('wallet'))
    
    return render_template('request_money.html')

@app.route('/transaction/cancel/<transaction_id>', methods=['POST'])
def cancel_transaction(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if not transaction_id or not re.match(r'^[a-f0-9-]{36}$', transaction_id):
        flash('유효하지 않은 거래 ID입니다.')
        return redirect(url_for('wallet'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 트랜잭션 정보 조회
    cursor.execute("""
        SELECT * FROM "transaction" 
        WHERE id = ? AND sender_id = ? AND status = 'completed'
        AND datetime(timestamp) > datetime('now', '-1 day')
    """, (transaction_id, session['user_id']))
    transaction = cursor.fetchone()
    
    if not transaction:
        flash('취소할 수 없는 거래입니다. (24시간 이내 거래만 취소 가능)')
        return redirect(url_for('wallet'))
    
    # 트랜잭션 시작
    try:
        cursor.execute("BEGIN TRANSACTION")
        
        # 송신자에게 금액 반환
        cursor.execute("UPDATE wallet SET balance = balance + ? WHERE user_id = ?", 
                      (transaction['amount'], session['user_id']))
        
        # 수신자 잔액 감소
        cursor.execute("UPDATE wallet SET balance = balance - ? WHERE user_id = ?", 
                      (transaction['amount'], transaction['receiver_id']))
        
        # 트랜잭션 상태 업데이트
        cursor.execute("UPDATE \"transaction\" SET status = 'canceled' WHERE id = ?", (transaction_id,))
        
        cursor.execute("COMMIT")
        flash('송금이 취소되었습니다.')
        
    except Exception as e:
        cursor.execute("ROLLBACK")
        flash('송금 취소 중 오류가 발생했습니다.')
    
    return redirect(url_for('wallet'))

# 상품 검색 기능
@app.route('/search')
def search_products():
    query = request.args.get('query', '')
    min_price = request.args.get('min_price', type=float, default=0)
    max_price = request.args.get('max_price', type=float)
    sort_by = request.args.get('sort_by', 'title')
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 기본 쿼리
        sql = """
            SELECT p.*, u.username as seller_name 
            FROM product p
            JOIN user u ON p.seller_id = u.id
            WHERE 1=1
        """
        params = []
        
        # 검색어가 있는 경우
        if query:
            sql += " AND (title LIKE ? OR description LIKE ?)"
            params.extend(['%' + query + '%', '%' + query + '%'])
        
        # 가격 범위 필터
        if min_price is not None:
            sql += " AND CAST(price AS REAL) >= ?"
            params.append(min_price)
        
        if max_price is not None and max_price > 0:
            sql += " AND CAST(price AS REAL) <= ?"
            params.append(max_price)
        
        # 정렬
        if sort_by == 'price_asc':
            sql += " ORDER BY CAST(price AS REAL) ASC"
        elif sort_by == 'price_desc':
            sql += " ORDER BY CAST(price AS REAL) DESC"
        else:  # 기본은 제목 순
            sql += " ORDER BY title ASC"
        
        cursor.execute(sql, params)
        products = cursor.fetchall()
        
        return render_template('search_results.html', products=products, query=query, 
                            min_price=min_price, max_price=max_price, sort_by=sort_by)
    except Exception as e:
        flash(f'검색 중 오류가 발생했습니다: {str(e)}')
        return redirect(url_for('dashboard'))

# 채팅 목록 페이지
@app.route('/chats')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 모든 채팅 상대 목록
    cursor.execute("""
        SELECT DISTINCT 
            CASE 
                WHEN pm.sender_id = ? THEN pm.receiver_id 
                ELSE pm.sender_id 
            END as chat_partner_id,
            u.username as chat_partner_name,
            MAX(pm.timestamp) as last_message_time,
            (SELECT COUNT(*) FROM private_message 
             WHERE receiver_id = ? AND sender_id = chat_partner_id AND is_read = 0) as unread_count
        FROM private_message pm
        JOIN user u ON (
            (pm.sender_id = ? AND pm.receiver_id = u.id) OR 
            (pm.receiver_id = ? AND pm.sender_id = u.id)
        )
        WHERE pm.sender_id = ? OR pm.receiver_id = ?
        GROUP BY chat_partner_id
        ORDER BY last_message_time DESC
    """, (session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id']))
    
    chats = cursor.fetchall()
    return render_template('chat_list.html', chats=chats)

# 1:1 채팅 기능
@app.route('/chat/<user_id>')
def private_chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if not user_id or not re.match(r'^[a-f0-9-]{36}$', user_id):
        flash('유효하지 않은 사용자 ID입니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 채팅 상대방 정보 조회
    cursor.execute("SELECT id, username FROM user WHERE id = ?", (user_id,))
    chat_partner = cursor.fetchone()
    
    if not chat_partner:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('dashboard'))
    
    # 채팅 내역 불러오기
    cursor.execute("""
        SELECT pm.*, s.username as sender_name, r.username as receiver_name 
        FROM private_message pm
        JOIN user s ON pm.sender_id = s.id
        JOIN user r ON pm.receiver_id = r.id
        WHERE (pm.sender_id = ? AND pm.receiver_id = ?) OR (pm.sender_id = ? AND pm.receiver_id = ?)
        ORDER BY pm.timestamp ASC
    """, (session['user_id'], user_id, user_id, session['user_id']))
    messages = cursor.fetchall()
    
    # 읽지 않은 메시지 읽음 처리
    cursor.execute("""
        UPDATE private_message SET is_read = 1
        WHERE receiver_id = ? AND sender_id = ? AND is_read = 0
    """, (session['user_id'], user_id))
    db.commit()
    
    return render_template('private_chat.html', chat_partner=chat_partner, messages=messages)

@app.route('/send_private_message', methods=['POST'])
def send_private_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    receiver_id = request.form.get('receiver_id')
    message_text = sanitize_input(request.form.get('message'))
    
    if not receiver_id or not re.match(r'^[a-f0-9-]{36}$', receiver_id):
        flash('유효하지 않은 수신자 ID입니다.')
        return redirect(url_for('dashboard'))
    
    if not message_text:
        flash('메시지를 입력해주세요.')
        return redirect(url_for('private_chat', user_id=receiver_id))
    
    db = get_db()
    cursor = db.cursor()
    
    # 수신자 확인
    cursor.execute("SELECT id FROM user WHERE id = ?", (receiver_id,))
    if not cursor.fetchone():
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('dashboard'))
    
    # 메시지 저장
    message_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO private_message (id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)",
        (message_id, session['user_id'], receiver_id, message_text)
    )
    db.commit()
    
    return redirect(url_for('private_chat', user_id=receiver_id))

# 상품 업로드 수정
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = sanitize_input(request.form['title'])
        description = sanitize_input(request.form['description'])
        price = request.form['price']
        
        # 입력 검증
        if not title or len(title) < 2:
            flash('제목은 최소 2자 이상이어야 합니다.')
            return redirect(url_for('new_product'))
            
        if not description:
            flash('상품 설명을 입력해주세요.')
            return redirect(url_for('new_product'))
            
        if not validate_price(price):
            flash('유효한 가격을 입력해주세요.')
            return redirect(url_for('new_product'))
            
        # 이미지 업로드 처리
        image_path = ''
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # 파일명 충돌 방지를 위한 UUID 추가
                unique_filename = f"{str(uuid.uuid4())}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                # DB에 저장할 상대 경로
                image_path = f"uploads/{unique_filename}"
            
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image_path) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'], image_path)
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 신고 기능 강화
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        target_type = request.form['target_type']  # 'user' 또는 'product'
        reason = sanitize_input(request.form['reason'])
        
        # 입력 검증
        if not target_id or not re.match(r'^[a-f0-9-]{36}$', target_id):
            flash('유효하지 않은 대상 ID입니다.')
            return redirect(url_for('report'))
            
        if not reason or len(reason) < 10:
            flash('신고 사유는 최소 10자 이상이어야 합니다.')
            return redirect(url_for('report'))
            
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        
        # 리포트 저장
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        
        # 대상 유형에 따라 신고 카운트 증가
        if target_type == 'user':
            cursor.execute("UPDATE user SET report_count = report_count + 1 WHERE id = ?", (target_id,))
            
            # 일정 횟수 이상 신고된 유저 자동 휴면 처리
            cursor.execute("SELECT report_count FROM user WHERE id = ?", (target_id,))
            user = cursor.fetchone()
            if user and user['report_count'] >= 5:
                cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (target_id,))
                
        elif target_type == 'product':
            cursor.execute("UPDATE product SET report_count = report_count + 1 WHERE id = ?", (target_id,))
            
            # 일정 횟수 이상 신고된 상품 자동 삭제
            cursor.execute("SELECT report_count FROM product WHERE id = ?", (target_id,))
            product = cursor.fetchone()
            if product and product['report_count'] >= 3:
                cursor.execute("DELETE FROM product WHERE id = ?", (target_id,))
        
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 관리자 기능
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 최근 신고 내역
    cursor.execute("""
        SELECT r.*, u1.username as reporter_name, 
        CASE 
            WHEN EXISTS (SELECT 1 FROM user WHERE id = r.target_id) THEN 
                (SELECT username FROM user WHERE id = r.target_id)
            WHEN EXISTS (SELECT 1 FROM product WHERE id = r.target_id) THEN 
                (SELECT title FROM product WHERE id = r.target_id)
            ELSE '알 수 없음'
        END as target_name,
        CASE 
            WHEN EXISTS (SELECT 1 FROM user WHERE id = r.target_id) THEN 'user'
            WHEN EXISTS (SELECT 1 FROM product WHERE id = r.target_id) THEN 'product'
            ELSE 'unknown'
        END as target_type
        FROM report r
        JOIN user u1 ON r.reporter_id = u1.id
        ORDER BY r.rowid DESC LIMIT 10
    """)
    reports = cursor.fetchall()

    # 신고 건수가 있는 사용자 목록
    cursor.execute("SELECT * FROM user WHERE report_count > 0 ORDER BY report_count DESC")
    reported_users = cursor.fetchall()
    
    # 휴면 계정 목록
    cursor.execute("SELECT * FROM user WHERE is_active = 0")
    inactive_users = cursor.fetchall()
    
    # 신고 횟수가 많은 상품 목록
    # cursor.execute("SELECT * FROM product WHERE report_count > 0 ORDER BY report_count DESC LIMIT 10")
    # reported_products = cursor.fetchall()
    cursor.execute("SELECT p.*, u.username as seller_name FROM product p JOIN user u ON p.seller_id = u.id WHERE p.report_count > 0 ORDER BY p.report_count DESC")
    reported_products = cursor.fetchall()

    # 전체 통계
    cursor.execute("SELECT COUNT(*) as total FROM user WHERE role != 'admin'")
    total_users = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM product")
    total_products = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM report")
    total_reports = cursor.fetchone()['total']
    
    return render_template('admin_dashboard.html', 
                          reports=reports, 
                          reported_users=reported_users,
                          inactive_users=inactive_users, 
                          reported_products=reported_products,
                          total_users=total_users,
                          total_products=total_products,
                          total_reports=total_reports)

# 사용자 관리 기능
@app.route('/admin/user/<user_id>', methods=['POST'])
@admin_required
def admin_user_action(user_id):
    action = request.form.get('action')
    
    if not user_id or not re.match(r'^[a-f0-9-]{36}$', user_id):
        flash('유효하지 않은 사용자 ID입니다.')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    if action == 'activate':
        cursor.execute("UPDATE user SET is_active = 1, report_count = 0 WHERE id = ?", (user_id,))
        flash('사용자가 활성화되었습니다.')
    elif action == 'deactivate':
        cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (user_id,))
        flash('사용자가 비활성화되었습니다.')
    elif action == 'delete':
        # 사용자와 관련된 모든 데이터 삭제
        cursor.execute("DELETE FROM product WHERE seller_id = ?", (user_id,))
        cursor.execute("DELETE FROM wallet WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM private_message WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
        cursor.execute("DELETE FROM \"transaction\" WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
        cursor.execute("DELETE FROM report WHERE reporter_id = ? OR target_id = ?", (user_id, user_id))
        cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
        flash('사용자와 관련된 모든 데이터가 삭제되었습니다.')
    elif action == 'clear_reports':
        cursor.execute("UPDATE user SET report_count = 0 WHERE id = ?", (user_id,))
        cursor.execute("DELETE FROM report WHERE target_id = ?", (user_id,))
        flash('사용자의 모든 신고가 초기화되었습니다.')
    
    db.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/product/<product_id>', methods=['POST'])
@admin_required
def admin_product_action(product_id):
    action = request.form.get('action')
    
    if not product_id or not re.match(r'^[a-f0-9-]{36}$', product_id):
        flash('유효하지 않은 상품 ID입니다.')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    if action == 'clear_reports':
        cursor.execute("UPDATE product SET report_count = 0 WHERE id = ?", (product_id,))
        cursor.execute("DELETE FROM report WHERE target_id = ?", (product_id,))
        flash('상품 신고가 초기화되었습니다.')
    elif action == 'delete':
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        cursor.execute("DELETE FROM report WHERE target_id = ?", (product_id,))
        flash('상품이 삭제되었습니다.')
    elif action == 'toggle_sold':
        cursor.execute("UPDATE product SET is_sold = CASE WHEN is_sold = 1 THEN 0 ELSE 1 END WHERE id = ?", (product_id,))
        flash('상품의 판매 상태가 변경되었습니다.')
    
    db.commit()
    return redirect(url_for('admin_products'))

# 게시물 삭제 라우트
@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ? AND seller_id = ?", 
                  (product_id, session['user_id']))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

# 게시물 수정 라우트
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        title = sanitize_input(request.form['title'])
        description = sanitize_input(request.form['description'])
        price = request.form['price']
        
        # 입력 검증
        if not title or len(title) < 2:
            flash('제목은 최소 2자 이상이어야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
            
        if not description:
            flash('상품 설명을 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
            
        if not validate_price(price):
            flash('유효한 가격을 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        # 이미지 업로드 처리
        image_update = False
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{str(uuid.uuid4())}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_path = f"uploads/{unique_filename}"
                image_update = True
        
        # 이미지 업데이트 여부에 따라 다른 쿼리 사용
        if image_update:
            cursor.execute(
                "UPDATE product SET title = ?, description = ?, price = ?, image_path = ? WHERE id = ? AND seller_id = ?",
                (title, description, price, image_path, product_id, session['user_id'])
            )
        else:
            cursor.execute(
                "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ? AND seller_id = ?",
                (title, description, price, product_id, session['user_id'])
            )
        
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 기존 상품 정보 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", 
                  (product_id, session['user_id']))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없거나 접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_product.html', product=product)

# 이미 있는 관리자 기능의 링크 추가
@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    # 정렬 옵션
    sort_by = request.args.get('sort', 'username')
    order = request.args.get('order', 'asc')
    
    if sort_by not in ['username', 'report_count', 'is_active', 'role']:
        sort_by = 'username'
    if order not in ['asc', 'desc']:
        order = 'asc'
    cursor.execute(f"SELECT * FROM user ORDER BY {sort_by} {order}")
    users = cursor.fetchall()
    return render_template('admin_users.html', users=users, sort_by=sort_by, order=order)

@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cursor = db.cursor()
        # 정렬 옵션
    sort_by = request.args.get('sort', 'title')
    order = request.args.get('order', 'asc')
    
    if sort_by not in ['title', 'price', 'report_count', 'is_sold']:
        sort_by = 'title'
    if order not in ['asc', 'desc']:
        order = 'asc'
    cursor.execute(f"""
        SELECT p.*, u.username as seller_name 
        FROM product p 
        JOIN user u ON p.seller_id = u.id 
        ORDER BY {sort_by} {order}
    """)
    products = cursor.fetchall()
    return render_template('admin_products.html', products=products, sort_by=sort_by, order=order)




@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            r.*,
            u1.username as reporter_name,
            CASE 
                WHEN EXISTS (SELECT 1 FROM user WHERE id = r.target_id) THEN 
                    (SELECT username FROM user WHERE id = r.target_id)
                WHEN EXISTS (SELECT 1 FROM product WHERE id = r.target_id) THEN 
                    (SELECT title FROM product WHERE id = r.target_id)
                ELSE '알 수 없음'
            END as target_name,
            CASE 
                WHEN EXISTS (SELECT 1 FROM user WHERE id = r.target_id) THEN 'user'
                WHEN EXISTS (SELECT 1 FROM product WHERE id = r.target_id) THEN 'product'
                ELSE 'unknown'
            END as target_type
        FROM report r
        JOIN user u1 ON r.reporter_id = u1.id
        ORDER BY r.rowid DESC
    """)
    reports = cursor.fetchall()
    return render_template('admin_reports.html', reports=reports)

# 신고 처리 기능 추가
@app.route('/admin/report/<report_id>', methods=['POST'])
@admin_required
def admin_report_action(report_id):
    action = request.form.get('action')
    
    if not report_id or not re.match(r'^[a-f0-9-]{36}$', report_id):
        flash('유효하지 않은 신고 ID입니다.')
        return redirect(url_for('admin_reports'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 신고 정보 조회
    cursor.execute("SELECT * FROM report WHERE id = ?", (report_id,))
    report = cursor.fetchone()
    
    if not report:
        flash('존재하지 않는 신고입니다.')
        return redirect(url_for('admin_reports'))
    
    if action == 'delete':
        cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
        flash('신고가 삭제되었습니다.')
    elif action == 'process':
        # 신고된 대상이 사용자인지 상품인지 확인
        cursor.execute("SELECT 1 FROM user WHERE id = ?", (report['target_id'],))
        is_user = cursor.fetchone() is not None
        
        if is_user:
            # 사용자 비활성화
            cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (report['target_id'],))
            flash('신고된 사용자가 비활성화되었습니다.')
        else:
            # 상품 삭제
            cursor.execute("DELETE FROM product WHERE id = ?", (report['target_id'],))
            flash('신고된 상품이 삭제되었습니다.')
        
        # 신고 처리 완료
        cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    
    db.commit()
    return redirect(url_for('admin_reports'))

if __name__ == '__main__':
    init_db()  # 기본 테이블 생성
    # extend_db()  # 추가 테이블 생성
    create_admin_account()  # 관리자 계정 생성
    app.run(debug=True)  # 개발 중에는 debug=True, 프로덕션에서는 False