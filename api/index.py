import base64
import hashlib
import os
import secrets
import datetime
from decimal import Decimal, InvalidOperation
import io
import math
import uuid
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, abort
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from urllib.parse import quote

# โหลด Environment Variables
load_dotenv()

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    if os.getenv('VERCEL') == '1':
        raise RuntimeError('FLASK_SECRET_KEY must be configured in production')
    app.secret_key = secrets.token_hex(32)

# กำหนด Security Headers และ Cookie Properties ตาม OWASP Standard
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('VERCEL', '0') == '1' # Secure เมื่ออยู่บน Production/Vercel
)

FIREBASE_API_KEY = os.getenv('FIREBASE_API_KEY')
FIREBASE_DB_URL = os.getenv('FIREBASE_DATABASE_URL')
FIREBASE_DB_SECRET = os.getenv('FIREBASE_DATABASE_SECRET')
SUPABASE_URL = os.getenv('SUPABASE_URL', '').rstrip('/')
SUPABASE_STORAGE_BUCKET = os.getenv('SUPABASE_STORAGE_BUCKET', 'portfolio-images')
PROFILE_IMAGE_MAX_BYTES = 5 * 1024 * 1024
PROFILE_IMAGE_TYPES = {
    'image/jpeg': ('jpg', lambda data: data.startswith(b'\xff\xd8\xff')),
    'image/png': ('png', lambda data: data.startswith(b'\x89PNG\r\n\x1a\n')),
    'image/webp': ('webp', lambda data: len(data) >= 12 and data[:4] == b'RIFF' and data[8:12] == b'WEBP')
}
app.config['MAX_CONTENT_LENGTH'] = PROFILE_IMAGE_MAX_BYTES + 128 * 1024

class ProfilePhotoStorageConfigurationError(RuntimeError):
    pass

class SupabaseStorageError(RuntimeError):
    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(f'Supabase Storage returned HTTP {status_code}')

# --- OWASP Security Middleware ---
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data: blob: https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
    if is_authenticated() or request.endpoint == 'logout':
        response.headers['Cache-Control'] = 'no-store, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Vary'] = 'Cookie'
    return response

def _session_token_cipher():
    key = base64.urlsafe_b64encode(hashlib.sha256(app.secret_key.encode('utf-8')).digest())
    return Fernet(key)

def set_firebase_id_token(token):
    session['_firebase_id_token'] = _session_token_cipher().encrypt(token.encode('utf-8')).decode('ascii')
    session.pop('idToken', None)

def get_firebase_id_token():
    encrypted_token = session.get('_firebase_id_token')
    if encrypted_token:
        try:
            return _session_token_cipher().decrypt(encrypted_token.encode('ascii')).decode('utf-8')
        except (InvalidToken, ValueError):
            session.pop('_firebase_id_token', None)
            return None

    legacy_token = session.pop('idToken', None)
    if legacy_token:
        set_firebase_id_token(legacy_token)
    return legacy_token

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

@app.before_request
def sync_session_profile_photo():
    if not is_authenticated():
        return

    if 'idToken' in session:
        get_firebase_id_token()
    if session.get('profile_photo_loaded'):
        return

    try:
        metadata = get_profile_photo_metadata(session['user_id'])
        session['photo_file_id'] = metadata.get('photo_file_id')
        session['photo_updated_at'] = metadata.get('updated_at')
    except requests.RequestException:
        session.pop('photo_file_id', None)
        session.pop('photo_updated_at', None)
        app.logger.warning('Could not sync profile image metadata for current session')
    session['profile_photo_loaded'] = True

@app.errorhandler(413)
def profile_upload_too_large(_error):
    if is_authenticated():
        flash('รูปโปรไฟล์ต้องมีขนาดไม่เกิน 5 MB', 'warning')
        return redirect(url_for('profile'))
    return 'Request too large', 413

def supabase_storage_request(method, path, **kwargs):
    secret_key = os.getenv('SUPABASE_SECRET_KEY', '')
    if not SUPABASE_URL or not secret_key or not SUPABASE_STORAGE_BUCKET:
        raise ProfilePhotoStorageConfigurationError('Supabase Storage settings are incomplete')

    headers = kwargs.pop('headers', {})
    headers['apikey'] = secret_key
    response = requests.request(
        method,
        f'{SUPABASE_URL}/storage/v1/{path.lstrip("/")}',
        headers=headers,
        timeout=20,
        **kwargs
    )
    if not response.ok:
        raise SupabaseStorageError(response.status_code)
    return response

def get_profile_photo_metadata(user_id):
    response = requests.get(
        f"{FIREBASE_DB_URL}/profiles/{user_id}.json?auth={FIREBASE_DB_SECRET}",
        timeout=10
    )
    if not response.ok:
        raise requests.RequestException('Could not load profile metadata')
    data = response.json()
    return data if isinstance(data, dict) else {}

def delete_profile_photo_file(file_id):
    if not file_id:
        return
    provider, separator, object_path = file_id.partition(':')
    if not separator or provider != 'supabase':
        raise ValueError('Unknown profile image storage provider')
    bucket = quote(SUPABASE_STORAGE_BUCKET, safe='')
    supabase_storage_request(
        'DELETE',
        f'object/{bucket}',
        json={'prefixes': [object_path]},
        headers={'Content-Type': 'application/json'}
    )

def get_pending_profile_photo_ids(metadata):
    configured_ids = metadata.get('pending_delete_file_ids') or []
    if not isinstance(configured_ids, list):
        configured_ids = []
    return list(dict.fromkeys(
        file_id for file_id in configured_ids
        if isinstance(file_id, str) and file_id.startswith('supabase:')
    ))

def retry_pending_profile_photo_deletions(user_id, metadata):
    pending_ids = get_pending_profile_photo_ids(metadata)
    if not pending_ids:
        return []

    remaining_ids = []
    for file_id in pending_ids:
        try:
            delete_profile_photo_file(file_id)
        except (RuntimeError, requests.RequestException, ValueError):
            app.logger.exception('Could not delete pending profile image')
            remaining_ids.append(file_id)

    if len(remaining_ids) != len(pending_ids):
        try:
            response = requests.patch(
                f"{FIREBASE_DB_URL}/profiles/{user_id}.json?auth={FIREBASE_DB_SECRET}",
                json={'pending_delete_file_ids': remaining_ids or None},
                timeout=10
            )
            if not response.ok:
                app.logger.error('Could not update pending profile image deletion list: status=%s', response.status_code)
                return pending_ids
        except requests.RequestException:
            app.logger.exception('Could not update pending profile image deletion list')
            return pending_ids
    return remaining_ids

def upload_profile_photo(file_bytes, mime_type, extension, user_id):
    object_path = f'profile-photos/{user_id}/{uuid.uuid4().hex}.{extension}'
    bucket = quote(SUPABASE_STORAGE_BUCKET, safe='')
    encoded_path = quote(object_path, safe='/')
    supabase_storage_request(
        'POST',
        f'object/{bucket}/{encoded_path}',
        data=file_bytes,
        headers={'Content-Type': mime_type, 'x-upsert': 'false'}
    )
    return {'file_id': object_path, 'mime_type': mime_type, 'storage': 'supabase'}

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
            session.clear()
            session['user_id'] = data['localId']
            session['email'] = data['email']
            set_firebase_id_token(data['idToken'])
            session['display_name'] = data.get('displayName', '')
            try:
                photo_metadata = get_profile_photo_metadata(data['localId'])
                session['photo_file_id'] = photo_metadata.get('photo_file_id')
                session['photo_updated_at'] = photo_metadata.get('updated_at')
            except requests.RequestException:
                session.pop('photo_file_id', None)
                session.pop('photo_updated_at', None)
                app.logger.warning('Could not load profile image metadata at login')
            flash('เข้าสู่ระบบสำเร็จ', 'success')
            return redirect(url_for('users_dashboard'))
        else:
            flash('อีเมลหรือรหัสผ่านไม่ถูกต้อง', 'danger')

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    if is_authenticated() and not verify_csrf():
        abort(403)
    session.clear()
    flash('ออกจากระบบเรียบร้อย', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not is_authenticated():
        return redirect(url_for('login'))

    if request.method == 'GET':
        profile_data = {
            'display_name': session.get('display_name', ''),
            'email': session.get('email', ''),
            'photo_file_id': None,
            'photo_mime_type': None,
            'photo_updated_at': None
        }
        try:
            lookup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={FIREBASE_API_KEY}"
            response = requests.post(lookup_url, json={'idToken': get_firebase_id_token()}, timeout=10)
            if response.ok:
                users = response.json().get('users', [])
                if users:
                    profile_data['display_name'] = users[0].get('displayName', '')
                    profile_data['email'] = users[0].get('email', profile_data['email'])
                    session['display_name'] = profile_data['display_name']
                    session['email'] = profile_data['email']
        except requests.RequestException:
            flash('โหลดข้อมูลบัญชีล่าสุดไม่สำเร็จ กำลังแสดงข้อมูลจากการเข้าสู่ระบบ', 'warning')

        try:
            photo_metadata = get_profile_photo_metadata(session['user_id'])
            pending_deletions = retry_pending_profile_photo_deletions(session['user_id'], photo_metadata)
            profile_data['photo_file_id'] = photo_metadata.get('photo_file_id')
            profile_data['photo_mime_type'] = photo_metadata.get('photo_mime_type')
            profile_data['photo_updated_at'] = photo_metadata.get('updated_at')
            session['photo_file_id'] = profile_data['photo_file_id']
            session['photo_updated_at'] = profile_data['photo_updated_at']
            if pending_deletions:
                flash('ยังลบรูปเดิมบางไฟล์ไม่สำเร็จ ระบบจะลองอีกครั้งอัตโนมัติ', 'warning')
        except requests.RequestException:
            app.logger.exception('Could not load profile image metadata')

        return render_template('profile.html', profile=profile_data)

    if not verify_csrf():
        flash('CSRF Token Invalid', 'danger')
        return redirect(url_for('profile'))

    action = request.form.get('action')
    current_email = session.get('email', '')
    auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
    update_url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_API_KEY}"

    if action == 'upload_photo':
        image = request.files.get('profile_photo')
        if not image or not image.filename:
            flash('กรุณาเลือกรูปโปรไฟล์ก่อนอัปโหลด', 'warning')
            return redirect(url_for('profile'))

        image_bytes = image.stream.read(PROFILE_IMAGE_MAX_BYTES + 1)
        if not image_bytes or len(image_bytes) > PROFILE_IMAGE_MAX_BYTES:
            flash('รูปโปรไฟล์ต้องมีขนาดไม่เกิน 5 MB', 'warning')
            return redirect(url_for('profile'))

        image_type = next(
            ((mime_type, extension) for mime_type, (extension, signature_check) in PROFILE_IMAGE_TYPES.items()
             if signature_check(image_bytes)),
            None
        )
        if not image_type:
            flash('รองรับไฟล์รูป JPEG, PNG หรือ WebP เท่านั้น', 'warning')
            return redirect(url_for('profile'))

        mime_type, extension = image_type
        try:
            old_metadata = get_profile_photo_metadata(session['user_id'])
            pending_ids = get_pending_profile_photo_ids(old_metadata)
            if old_metadata.get('photo_file_id') and old_metadata.get('photo_storage') == 'supabase':
                pending_ids.append(f"supabase:{old_metadata['photo_file_id']}")
            uploaded = upload_profile_photo(image_bytes, mime_type, extension, session['user_id'])
        except ProfilePhotoStorageConfigurationError:
            app.logger.exception('Supabase Storage configuration is incomplete')
            flash('กรุณาตั้งค่า SUPABASE_URL และ SUPABASE_SECRET_KEY ใน environment ก่อนอัปโหลดรูป', 'danger')
            return redirect(url_for('profile'))
        except SupabaseStorageError as error:
            app.logger.exception('Profile image upload failed')
            if error.status_code == 404:
                flash('ไม่พบ bucket ใน Supabase ตรวจชื่อ bucket และเปิด Storage ของโปรเจกต์แล้ว', 'danger')
            elif error.status_code == 403:
                flash('Supabase ปฏิเสธการอัปโหลด ตรวจว่าใช้ Secret key ฝั่ง server และ bucket policy อนุญาตการเขียน', 'danger')
            else:
                flash(f'อัปโหลด Supabase Storage ไม่สำเร็จ (HTTP {error.status_code})', 'danger')
            return redirect(url_for('profile'))
        except (RuntimeError, requests.RequestException, ValueError):
            app.logger.exception('Profile image upload failed')
            flash('อัปโหลด Supabase Storage ไม่สำเร็จ กรุณาตรวจสอบการเชื่อมต่อแล้วลองใหม่', 'danger')
            return redirect(url_for('profile'))

        new_metadata = {
            'photo_file_id': uploaded['file_id'],
            'photo_mime_type': uploaded['mime_type'],
            'photo_storage': uploaded['storage'],
            'updated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'pending_delete_file_ids': list(dict.fromkeys(pending_ids)) or None
        }
        try:
            database_response = requests.patch(
                f"{FIREBASE_DB_URL}/profiles/{session['user_id']}.json?auth={FIREBASE_DB_SECRET}",
                json=new_metadata,
                timeout=10
            )
        except requests.RequestException:
            database_response = None

        if not database_response or not database_response.ok:
            try:
                delete_profile_photo_file(f"supabase:{uploaded['file_id']}")
            except (RuntimeError, requests.RequestException, ValueError):
                app.logger.exception('Could not clean up uncommitted profile image')
            flash('บันทึกข้อมูลรูปโปรไฟล์ไม่สำเร็จ กรุณาลองใหม่', 'danger')
            return redirect(url_for('profile'))

        session['photo_file_id'] = uploaded['file_id']
        session['photo_updated_at'] = new_metadata['updated_at']
        pending_deletions = retry_pending_profile_photo_deletions(session['user_id'], new_metadata)
        if pending_deletions:
            flash('เปลี่ยนรูปแล้ว แต่ลบรูปเดิมจาก Supabase Storage ไม่สำเร็จ ระบบจะลองอีกครั้ง', 'warning')
            return redirect(url_for('profile'))

        flash('อัปโหลดรูปโปรไฟล์เรียบร้อยแล้ว', 'success')
        return redirect(url_for('profile'))

    if action == 'delete_photo':
        try:
            old_metadata = get_profile_photo_metadata(session['user_id'])
            if not old_metadata.get('photo_file_id'):
                flash('ไม่มีรูปโปรไฟล์ให้ลบ', 'info')
                return redirect(url_for('profile'))
            pending_ids = get_pending_profile_photo_ids(old_metadata)
            if old_metadata.get('photo_storage') == 'supabase':
                pending_ids.append(f"supabase:{old_metadata['photo_file_id']}")
            pending_ids = list(dict.fromkeys(pending_ids))
            database_response = requests.patch(
                f"{FIREBASE_DB_URL}/profiles/{session['user_id']}.json?auth={FIREBASE_DB_SECRET}",
                json={
                    'photo_file_id': None,
                    'photo_mime_type': None,
                    'photo_storage': None,
                    'pending_delete_file_ids': pending_ids
                },
                timeout=10
            )
        except requests.RequestException:
            app.logger.exception('Could not remove profile image metadata')
            flash('ลบข้อมูลรูปโปรไฟล์ไม่สำเร็จ กรุณาลองใหม่', 'danger')
            return redirect(url_for('profile'))

        if not database_response.ok:
            flash('ลบข้อมูลรูปโปรไฟล์ไม่สำเร็จ กรุณาลองใหม่', 'danger')
            return redirect(url_for('profile'))
        session.pop('photo_file_id', None)
        session.pop('photo_updated_at', None)
        pending_deletions = retry_pending_profile_photo_deletions(
            session['user_id'],
            {'pending_delete_file_ids': pending_ids}
        )
        if pending_deletions:
            flash('นำรูปออกจากโปรไฟล์แล้ว แต่ลบไฟล์จาก Supabase Storage ไม่สำเร็จ ระบบจะลองอีกครั้ง', 'warning')
            return redirect(url_for('profile'))

        flash('ลบรูปโปรไฟล์เรียบร้อยแล้ว', 'success')
        return redirect(url_for('profile'))

    if action == 'update_profile':
        display_name = request.form.get('display_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        current_password = request.form.get('current_password', '')

        if not display_name or len(display_name) > 80:
            flash('กรุณากรอกชื่อที่แสดงไม่เกิน 80 ตัวอักษร', 'warning')
            return redirect(url_for('profile'))
        if not email or '@' not in email:
            flash('กรุณากรอกอีเมลให้ถูกต้อง', 'warning')
            return redirect(url_for('profile'))
        if display_name == session.get('display_name', '') and email == current_email:
            flash('ไม่มีข้อมูลที่เปลี่ยนแปลง', 'info')
            return redirect(url_for('profile'))

        if not current_password:
            flash('กรุณากรอกรหัสผ่านปัจจุบันเพื่อยืนยันการบันทึกข้อมูลบัญชี', 'warning')
            return redirect(url_for('profile'))
        try:
            auth_response = requests.post(
                auth_url,
                json={'email': current_email, 'password': current_password, 'returnSecureToken': True},
                timeout=10
            )
        except requests.RequestException:
            flash('เชื่อมต่อระบบยืนยันตัวตนไม่สำเร็จ กรุณาลองใหม่', 'danger')
            return redirect(url_for('profile'))
        if not auth_response.ok:
            flash('รหัสผ่านปัจจุบันไม่ถูกต้อง', 'danger')
            return redirect(url_for('profile'))
        id_token = auth_response.json().get('idToken', get_firebase_id_token())

        try:
            update_data = {
                'idToken': id_token,
                'displayName': display_name,
                'returnSecureToken': True
            }
            if email != current_email:
                update_data['email'] = email
            response = requests.post(
                update_url,
                json=update_data,
                timeout=10
            )
        except requests.RequestException:
            flash('เชื่อมต่อระบบโปรไฟล์ไม่สำเร็จ กรุณาลองใหม่', 'danger')
            return redirect(url_for('profile'))

        if not response.ok:
            try:
                error = response.json().get('error', {}).get('message', '')
            except (TypeError, ValueError):
                error = ''
            app.logger.error('Firebase profile update failed: status=%s code=%s', response.status_code, error)
            if error == 'EMAIL_EXISTS':
                message = 'อีเมลนี้ถูกใช้กับบัญชีอื่นแล้ว'
            elif error == 'INVALID_EMAIL':
                message = 'รูปแบบอีเมลไม่ถูกต้อง'
            elif error in {'TOKEN_EXPIRED', 'INVALID_ID_TOKEN'}:
                message = 'ยืนยันตัวตนไม่สำเร็จ กรุณาออกจากระบบแล้วเข้าสู่ระบบใหม่'
            else:
                message = 'บันทึกโปรไฟล์ไม่สำเร็จ กรุณาตรวจสอบข้อมูลแล้วลองใหม่'
            flash(message, 'danger')
            return redirect(url_for('profile'))

        data = response.json()
        session['display_name'] = data.get('displayName', display_name)
        session['email'] = data.get('email', email)
        set_firebase_id_token(data.get('idToken', id_token))
        flash('บันทึกโปรไฟล์เรียบร้อยแล้ว', 'success')
        return redirect(url_for('profile'))

    if action == 'change_password':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not current_password:
            flash('กรุณากรอกรหัสผ่านปัจจุบัน', 'warning')
            return redirect(url_for('profile'))
        if len(new_password) < 6:
            flash('รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร', 'warning')
            return redirect(url_for('profile'))
        if new_password != confirm_password:
            flash('ยืนยันรหัสผ่านใหม่ไม่ตรงกัน', 'warning')
            return redirect(url_for('profile'))

        try:
            auth_response = requests.post(
                auth_url,
                json={'email': current_email, 'password': current_password, 'returnSecureToken': True},
                timeout=10
            )
            if not auth_response.ok:
                flash('รหัสผ่านปัจจุบันไม่ถูกต้อง', 'danger')
                return redirect(url_for('profile'))

            response = requests.post(
                update_url,
                json={
                    'idToken': auth_response.json()['idToken'],
                    'password': new_password,
                    'returnSecureToken': True
                },
                timeout=10
            )
        except requests.RequestException:
            flash('เชื่อมต่อระบบยืนยันตัวตนไม่สำเร็จ กรุณาลองใหม่', 'danger')
            return redirect(url_for('profile'))

        if not response.ok:
            flash('เปลี่ยนรหัสผ่านไม่สำเร็จ กรุณาลองใหม่', 'danger')
            return redirect(url_for('profile'))

        set_firebase_id_token(response.json().get('idToken', auth_response.json()['idToken']))
        flash('เปลี่ยนรหัสผ่านเรียบร้อยแล้ว', 'success')
        return redirect(url_for('profile'))

    flash('ไม่พบคำสั่งที่ต้องการ', 'warning')
    return redirect(url_for('profile'))

@app.route('/profile/photo', methods=['GET'])
def profile_photo():
    if not is_authenticated():
        abort(404)

    try:
        metadata = get_profile_photo_metadata(session['user_id'])
        file_id = metadata.get('photo_file_id')
        mime_type = metadata.get('photo_mime_type')
        if not file_id or metadata.get('photo_storage') != 'supabase' or mime_type not in PROFILE_IMAGE_TYPES:
            abort(404)

        bucket = quote(SUPABASE_STORAGE_BUCKET, safe='')
        object_path = quote(file_id, safe='/')
        response_from_storage = supabase_storage_request(
            'GET',
            f'object/public/{bucket}/{object_path}'
        )
        image_stream = io.BytesIO(response_from_storage.content)
        response = send_file(image_stream, mimetype=mime_type, max_age=300)
        response.headers['Cache-Control'] = 'private, max-age=300'
        return response
    except (RuntimeError, requests.RequestException, ValueError):
        app.logger.exception('Could not load profile image')
        abort(404)

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
    payload = request.get_json(silent=True) or {}
    items = payload.get('items', [])

    if not items or not isinstance(items, list):
        return jsonify({"success": False, "message": "ข้อมูลไม่ถูกต้อง"}), 400

    updates = {}
    for item in items:
        if not isinstance(item, dict):
            return jsonify({"success": False, "message": "ข้อมูลรายการไม่ถูกต้อง"}), 400

        tx_type = item.get('type')
        category = item.get('category', '')
        description = item.get('description', '')
        amount_str = item.get('amount', 0)
        date_str = item.get('date', datetime.date.today().isoformat())
        payment_method = item.get('payment_method', 'เงินสด')

        if tx_type not in ['income', 'expense']:
            return jsonify({"success": False, "message": "ประเภทข้อมูลไม่ถูกต้อง"}), 400
        if not all(isinstance(value, str) for value in (category, description, date_str, payment_method)):
            return jsonify({"success": False, "message": "ข้อมูลรายการไม่ถูกต้อง"}), 400
        try:
            amount = float(amount_str)
            datetime.date.fromisoformat(date_str)
            if not math.isfinite(amount) or amount <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "จำนวนเงินหรือวันที่ไม่ถูกต้อง"}), 400

        payload = {
            "type": tx_type,
            "category": category.strip() or 'ทั่วไป',
            "description": description,
            "amount": amount,
            "date": date_str,
            "payment_method": payment_method.strip() or 'เงินสด',
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        updates[uuid.uuid4().hex] = payload

    try:
        response = requests.patch(
            f"{FIREBASE_DB_URL}/transactions/{user_id}.json?auth={FIREBASE_DB_SECRET}",
            json=updates,
            timeout=10
        )
    except requests.RequestException:
        app.logger.exception('Firebase batch transaction save failed')
        return jsonify({"success": False, "message": "เชื่อมต่อฐานข้อมูลไม่สำเร็จ กรุณาลองใหม่"}), 502

    if not response.ok:
        app.logger.error('Firebase batch transaction save rejected: status=%s body=%s', response.status_code, response.text)
        return jsonify({"success": False, "message": "ฐานข้อมูลปฏิเสธการบันทึก กรุณาลองใหม่"}), 502

    return jsonify({"success": True, "saved_count": len(updates)})

@app.route('/users/debt-add', methods=['POST'])
def add_debt_transaction():
    if not is_authenticated():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if not verify_csrf():
        return jsonify({"success": False, "message": "CSRF verification failed"}), 403

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"success": False, "message": "ข้อมูลไม่ถูกต้อง"}), 400
    debt_items = payload.get('items')
    date_str = payload.get('date', datetime.date.today().isoformat())
    if not isinstance(debt_items, list) or not 2 <= len(debt_items) <= 50:
        return jsonify({"success": False, "message": "กรุณากรอกรายการหนี้อย่างน้อย 2 รายการ (สูงสุด 50 รายการ)"}), 400
    if not isinstance(date_str, str):
        return jsonify({"success": False, "message": "วันที่ไม่ถูกต้อง"}), 400

    validated_items = []
    total = Decimal('0')
    maximum_amount = Decimal('999999999999.99')
    for item in debt_items:
        if not isinstance(item, dict):
            return jsonify({"success": False, "message": "ข้อมูลรายการหนี้ไม่ถูกต้อง"}), 400
        name = item.get('name')
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
            return jsonify({"success": False, "message": "กรุณาระบุชื่อเจ้าหนี้หรือรายการหนี้ไม่เกิน 120 ตัวอักษร"}), 400
        try:
            amount = Decimal(str(item.get('amount', '')))
            if not amount.is_finite() or amount <= 0 or amount > maximum_amount or amount != amount.quantize(Decimal('0.01')):
                raise InvalidOperation
        except (InvalidOperation, ValueError):
            return jsonify({"success": False, "message": "จำนวนเงินหนี้ต้องมากกว่า 0 และมีทศนิยมไม่เกิน 2 ตำแหน่ง"}), 400
        total += amount
        if total > maximum_amount:
            return jsonify({"success": False, "message": "ยอดหนี้รวมสูงเกินจำนวนที่ระบบรองรับ"}), 400
        validated_items.append({"name": name.strip(), "amount": float(amount)})

    try:
        datetime.date.fromisoformat(date_str)
    except ValueError:
        return jsonify({"success": False, "message": "วันที่ไม่ถูกต้อง"}), 400

    transaction_id = uuid.uuid4().hex
    transaction = {
        "type": "expense",
        "category": "หนี้สิน",
        "description": f"หนี้หลายทาง ({len(validated_items)} รายการ)",
        "amount": float(total),
        "date": date_str,
        "payment_method": "รวมรายการ",
        "debt_items": validated_items,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    try:
        response = requests.patch(
            f"{FIREBASE_DB_URL}/transactions/{session['user_id']}.json?auth={FIREBASE_DB_SECRET}",
            json={transaction_id: transaction},
            timeout=10
        )
    except requests.RequestException:
        app.logger.exception('Firebase debt transaction save failed')
        return jsonify({"success": False, "message": "เชื่อมต่อฐานข้อมูลไม่สำเร็จ กรุณาลองใหม่"}), 502

    if not response.ok:
        app.logger.error('Firebase debt transaction save rejected: status=%s body=%s', response.status_code, response.text)
        return jsonify({"success": False, "message": "ฐานข้อมูลปฏิเสธการบันทึก กรุณาลองใหม่"}), 502

    return jsonify({"success": True, "amount": float(total)})

# API สำหรับแก้ไขหลายรายการพร้อมกัน (Batch Update)
@app.route('/users/batch-update', methods=['POST'])
def batch_update_transactions():
    if not is_authenticated():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if not verify_csrf():
        return jsonify({"success": False, "message": "CSRF verification failed"}), 403

    payload = request.get_json(silent=True) or {}
    transaction_ids = payload.get('ids')
    changes = payload.get('changes')
    allowed_fields = {'type', 'category', 'description', 'amount', 'date', 'payment_method'}

    if not isinstance(transaction_ids, list) or not transaction_ids or not all(
        isinstance(tx_id, str) and tx_id for tx_id in transaction_ids
    ):
        return jsonify({"success": False, "message": "กรุณาเลือกรายการที่ต้องการแก้ไข"}), 400
    if not isinstance(changes, dict):
        return jsonify({"success": False, "message": "ข้อมูลที่แก้ไขไม่ถูกต้อง"}), 400

    changes = {field: value for field, value in changes.items() if field in allowed_fields}
    if not changes:
        return jsonify({"success": False, "message": "กรุณาระบุฟิลด์ที่ต้องการแก้ไข"}), 400

    if 'type' in changes and changes['type'] not in {'income', 'expense'}:
        return jsonify({"success": False, "message": "ประเภทข้อมูลไม่ถูกต้อง"}), 400
    if 'amount' in changes:
        try:
            changes['amount'] = float(changes['amount'])
            if changes['amount'] <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "จำนวนเงินต้องมากกว่า 0"}), 400
    for field in {'category', 'description', 'payment_method'} & changes.keys():
        if not isinstance(changes[field], str):
            return jsonify({"success": False, "message": "ข้อมูลที่แก้ไขไม่ถูกต้อง"}), 400
        changes[field] = changes[field].strip()
    if 'date' in changes:
        try:
            datetime.date.fromisoformat(changes['date'])
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "วันที่ไม่ถูกต้อง"}), 400

    updates = {tx_id: changes for tx_id in set(transaction_ids)}
    user_id = session['user_id']
    if {'amount', 'type'} & changes.keys():
        try:
            current_response = requests.get(
                f"{FIREBASE_DB_URL}/transactions/{user_id}.json?auth={FIREBASE_DB_SECRET}",
                timeout=10
            )
            if not current_response.ok:
                return jsonify({"success": False, "message": "ตรวจสอบรายการเดิมไม่สำเร็จ กรุณาลองใหม่"}), 502
            current_transactions = current_response.json() or {}
        except requests.RequestException:
            app.logger.exception('Firebase transaction validation request failed')
            return jsonify({"success": False, "message": "เชื่อมต่อฐานข้อมูลไม่สำเร็จ กรุณาลองใหม่"}), 502
        if any(
            isinstance(current_transactions.get(tx_id), dict)
            and current_transactions[tx_id].get('debt_items')
            for tx_id in set(transaction_ids)
        ):
            return jsonify({"success": False, "message": "ชุดหนี้มีรายการย่อยประกอบ กรุณาลบแล้วบันทึกชุดหนี้ใหม่เพื่อเปลี่ยนประเภทหรือยอดรวม"}), 400

    try:
        response = requests.patch(
            f"{FIREBASE_DB_URL}/transactions/{user_id}.json?auth={FIREBASE_DB_SECRET}",
            json=updates,
            timeout=10
        )
    except requests.RequestException:
        app.logger.exception('Firebase batch update request failed')
        return jsonify({"success": False, "message": "เชื่อมต่อฐานข้อมูลไม่สำเร็จ กรุณาลองใหม่"}), 502

    if not response.ok:
        app.logger.error('Firebase batch update rejected: status=%s body=%s', response.status_code, response.text)
        try:
            error_message = response.json().get('error')
        except ValueError:
            error_message = None
        message = f"ฐานข้อมูลปฏิเสธการแก้ไข: {error_message}" if error_message else "บันทึกการแก้ไขไม่สำเร็จ กรุณาลองอีกครั้ง"
        return jsonify({"success": False, "message": message}), 502

    return jsonify({"success": True, "updated_count": len(updates)})

@app.route('/users/batch-delete', methods=['POST'])
def batch_delete_transactions():
    if not is_authenticated():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if not verify_csrf():
        return jsonify({"success": False, "message": "CSRF verification failed"}), 403

    payload = request.get_json(silent=True) or {}
    transaction_ids = payload.get('ids')
    if not isinstance(transaction_ids, list) or not transaction_ids or not all(
        isinstance(tx_id, str) and tx_id for tx_id in transaction_ids
    ):
        return jsonify({"success": False, "message": "กรุณาเลือกรายการที่ต้องการลบ"}), 400

    updates = {tx_id: None for tx_id in set(transaction_ids)}
    user_id = session['user_id']
    try:
        response = requests.patch(
            f"{FIREBASE_DB_URL}/transactions/{user_id}.json?auth={FIREBASE_DB_SECRET}",
            json=updates,
            timeout=10
        )
    except requests.RequestException:
        app.logger.exception('Firebase batch delete request failed')
        return jsonify({"success": False, "message": "เชื่อมต่อฐานข้อมูลไม่สำเร็จ กรุณาลองใหม่"}), 502

    if not response.ok:
        app.logger.error('Firebase batch delete rejected: status=%s body=%s', response.status_code, response.text)
        return jsonify({"success": False, "message": "ลบรายการไม่สำเร็จ กรุณาลองอีกครั้ง"}), 502

    return jsonify({"success": True, "deleted_count": len(updates)})

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
    app.run(debug=os.getenv('FLASK_DEBUG') == '1' and os.getenv('VERCEL') != '1', port=5000)