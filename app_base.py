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


app = Flask(__name__)
# 안전한 랜덤 시크릿 키 생성
app.config['SECRET_KEY'] = os.urandom(24)
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)  # CSRF 보호 활성화

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
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
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
        db.commit()

# 입력 검증 함수들
def validate_username(username):
    if not username or not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False
    return True

def validate_password(password):
    if not password or len(password) < 8:
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

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
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
            flash('비밀번호는 최소 8자 이상이어야 합니다.')
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
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
            # session.permanent = True  # 세션 지속성 설정
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
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

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

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
    return render_template('profile.html', user=current_user)

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
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    # XSS 방지를 위한 메시지 정제
    if 'message' in data:
        data['message'] = sanitize_input(data['message'])
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 데이터베이스 스키마 추가
def extend_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
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
        
        # 사용자 역할 필드 추가 (관리자 여부)
        cursor.execute("PRAGMA table_info(user)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'role' not in columns:
            cursor.execute("ALTER TABLE user ADD COLUMN role TEXT DEFAULT 'user'")
        
        # 상품 이미지 URL 필드 추가
        cursor.execute("PRAGMA table_info(product)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'image_url' not in columns:
            cursor.execute("ALTER TABLE product ADD COLUMN image_url TEXT")
        
        # 신고 카운트 필드 추가
        if 'report_count' not in columns:
            cursor.execute("ALTER TABLE product ADD COLUMN report_count INTEGER DEFAULT 0")
        
        cursor.execute("PRAGMA table_info(user)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'report_count' not in columns:
            cursor.execute("ALTER TABLE user ADD COLUMN report_count INTEGER DEFAULT 0")
        if 'is_active' not in columns:
            cursor.execute("ALTER TABLE user ADD COLUMN is_active INTEGER DEFAULT 1")
            
        db.commit()

# 관리자 확인 데코레이터
from functools import wraps
from flask import abort

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
            abort(403)  # 권한 없음
        return f(*args, **kwargs)
    return decorated_function

# 페이 관련 라우트
@app.route('/wallet')
def wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    
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
        FROM transaction t
        JOIN user u1 ON t.sender_id = u1.id
        JOIN user u2 ON t.receiver_id = u2.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.timestamp DESC
    """, (session['user_id'], session['user_id']))
    transactions = cursor.fetchall()
    
    return render_template('wallet.html', wallet=wallet, transactions=transactions)

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
                "INSERT INTO transaction (id, sender_id, receiver_id, amount, message, status) VALUES (?, ?, ?, ?, ?, ?)",
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
        SELECT * FROM transaction 
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
        cursor.execute("UPDATE transaction SET status = 'canceled' WHERE id = ?", (transaction_id,))
        
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
    
    db = get_db()
    cursor = db.cursor()
    
    # 기본 쿼리
    sql = "SELECT * FROM product WHERE 1=1"
    params = []
    
    # 검색어가 있는 경우
    if query:
        sql += " AND (title LIKE ? OR description LIKE ?)"
        params.extend(['%' + query + '%', '%' + query + '%'])
    
    # 가격 범위 필터
    if min_price is not None:
        sql += " AND CAST(price AS REAL) >= ?"
        params.append(min_price)
    
    if max_price is not None:
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

# 상품 업로드 시 이미지 URL 추가
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = sanitize_input(request.form['title'])
        description = sanitize_input(request.form['description'])
        price = request.form['price']
        image_url = sanitize_input(request.form.get('image_url', ''))
        
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
            
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image_url) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'], image_url)
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
        SELECT r.*, u1.username as reporter_name, u2.username as target_name
        FROM report r
        JOIN user u1 ON r.reporter_id = u1.id
        JOIN user u2 ON r.target_id = u2.id
        ORDER BY rowid DESC LIMIT 10
    """)
    reports = cursor.fetchall()
    
    # 휴면 계정 목록
    cursor.execute("SELECT * FROM user WHERE is_active = 0")
    inactive_users = cursor.fetchall()
    
    # 신고 횟수가 많은 상품 목록
    cursor.execute("SELECT * FROM product WHERE report_count > 0 ORDER BY report_count DESC LIMIT 10")
    reported_products = cursor.fetchall()
    
    return render_template('admin_dashboard.html', reports=reports, 
                          inactive_users=inactive_users, reported_products=reported_products)

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
        # 사용자 삭제 처리
        cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
        flash('사용자가 삭제되었습니다.')
    
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
        flash('상품 신고가 초기화되었습니다.')
    elif action == 'delete':
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        flash('상품이 삭제되었습니다.')
    
    db.commit()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    init_db()  # 기본 테이블 생성
    extend_db()  # 추가 테이블 생성
    socketio.run(app, debug=False)  # 프로덕션 환경에서는 debug=False로 설정