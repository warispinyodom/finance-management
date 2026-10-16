import os
import secrets
import datetime
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from dotenv import load_dotenv

# โหลด Environment Variables
load_dotenv()

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))

# กำหนด Security Headers และ Cookie Properties ตาม OWASP Standard
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('VERCEL', '0') == '1' # Secure เมื่ออยู่บน Production/Vercel
)

FIREBASE_API_KEY = os.getenv('FIREBASE_API_KEY')
FIREBASE_DB_URL = os.getenv('FIREBASE_DATABASE_URL')
FIREBASE_DB_SECRET = os.getenv('FIREBASE_DATABASE_SECRET')

# --- OWASP Security Middleware ---
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
    return response

# สร้างและตรวจสอบ CSRF Token
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def verify_csrf():
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not token or token != session.get('_csrf_token'):
        return False
    return True

# Helper ตรวจสอบล็อกอิน
def is_authenticated():
    return 'user_id' in session

# --- Routes ---
@app.route('/')
def home():
    if is_authenticated():
        return redirect(url_for('users_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not verify_csrf():
            flash('CSRF Verification Failed!', 'danger')
            return redirect(url_for('register'))
            
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password or len(password) < 6:
            flash('อีเมลและรหัสผ่านต้องมีความยาวอย่างน้อย 6 ตัวอักษร', 'warning')
            return redirect(url_for('register'))

        # สมัครสมาชิกผ่าน Firebase Auth REST API
        auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
        res = requests.post(auth_url, json={"email": email, "password": password, "returnSecureToken": True})
        
        if res.status_code == 200:
            flash('ลงทะเบียนสำเร็จ! กรุณาเข้าสู่ระบบ', 'success')
            return redirect(url_for('login'))
        else:
            err_msg = res.json().get('error', {}).get('message', 'สมัครสมาชิกไม่สำเร็จ')
            flash(f'เกิดข้อผิดพลาด: {err_msg}', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not verify_csrf():
            flash('CSRF Verification Failed!', 'danger')
            return redirect(url_for('login'))

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        res = requests.post(auth_url, json={"email": email, "password": password, "returnSecureToken": True})
        
        if res.status_code == 200:
            data = res.json()
            session['user_id'] = data['localId']
            session['email'] = data['email']
            session['idToken'] = data['idToken']
            flash('เข้าสู่ระบบสำเร็จ', 'success')
            return redirect(url_for('users_dashboard'))
        else:
            flash('อีเมลหรือรหัสผ่านไม่ถูกต้อง', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('ออกจากระบบเรียบร้อย', 'info')
    return redirect(url_for('login'))

# --- หน้าบันทึกรายรับ-รายจ่าย /users ---
@app.route('/users', methods=['GET'])
def users_dashboard():
    if not is_authenticated():
        return redirect(url_for('login'))

    user_id = session['user_id']
    # ดึงข้อมูลการเงินจาก Firebase Realtime DB
    db_res = requests.get(f"{FIREBASE_DB_URL}/transactions/{user_id}.json?auth={FIREBASE_DB_SECRET}")
    raw_data = db_res.json() if db_res.status_code == 200 and db_res.json() else {}

    transactions = []
    total_income = 0.0
    total_expense = 0.0

    for key, item in raw_data.items():
        item['id'] = key
        amount = float(item.get('amount', 0))
        if item.get('type') == 'income':
            total_income += amount
        elif item.get('type') == 'expense':
            total_expense += amount
        transactions.append(item)

    # เรียงลำดับตามวันที่ล่าสุด
    transactions.sort(key=lambda x: x.get('date', ''), reverse=True)
    balance = total_income - total_expense

    return render_template('users.html', 
                           transactions=transactions, 
                           total_income=total_income, 
                           total_expense=total_expense, 
                           balance=balance,
                           email=session.get('email'))

# API สำหรับบันทึกแบบหลายรายการพร้อมกัน (Batch Add)
@app.route('/users/batch-add', methods=['POST'])
def batch_add_transactions():
    if not is_authenticated():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if not verify_csrf():
        return jsonify({"success": False, "message": "CSRF verification failed"}), 403

    user_id = session['user_id']
    items = request.json.get('items', [])

    if not items or not isinstance(items, list):
        return jsonify({"success": False, "message": "ข้อมูลไม่ถูกต้อง"}), 400

    saved_count = 0
    for item in items:
        # Data Sanitization & Server-side Validation
        tx_type = item.get('type')
        category = item.get('category', '').strip()
        description = item.get('description', '').strip()
        amount_str = item.get('amount', 0)
        date_str = item.get('date', datetime.date.today().isoformat())
        payment_method = item.get('payment_method', 'เงินสด')

        if tx_type not in ['income', 'expense']:
            continue
        try:
            amount = float(amount_str)
            if amount <= 0: continue
        except ValueError:
            continue

        payload = {
            "type": tx_type,
            "category": category or 'ทั่วไป',
            "description": description,
            "amount": amount,
            "date": date_str,
            "payment_method": payment_method,
            "created_at": datetime.datetime.utcnow().isoformat()
        }

        # บันทึกลง Firebase RTDB
        requests.post(f"{FIREBASE_DB_URL}/transactions/{user_id}.json?auth={FIREBASE_DB_SECRET}", json=payload)
        saved_count += 1

    return jsonify({"success": True, "saved_count": saved_count})

@app.route('/users/delete/<tx_id>', methods=['POST'])
def delete_transaction(tx_id):
    if not is_authenticated():
        return redirect(url_for('login'))
    if not verify_csrf():
        flash('CSRF Token Invalid', 'danger')
        return redirect(url_for('users_dashboard'))

    user_id = session['user_id']
    requests.delete(f"{FIREBASE_DB_URL}/transactions/{user_id}/{tx_id}.json?auth={FIREBASE_DB_SECRET}")
    flash('ลบรายการเรียบร้อยแล้ว', 'success')
    return redirect(url_for('users_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)