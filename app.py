import os
import uuid
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, send_from_directory, abort, session, jsonify)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-key-in-production-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)


# ==================== 数据模型 ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    invite_code_used = db.Column(db.String(50))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(500), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False, unique=True)
    size = db.Column(db.Integer)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), default='其他')
    version = db.Column(db.String(50), default='')
    download_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)
    note = db.Column(db.String(200))


# ==================== 辅助函数 ====================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


def format_size(size):
    """格式化文件大小"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


app.jinja_env.filters['format_size'] = format_size


# ==================== 前台路由 ====================

@app.route('/')
def index():
    user = get_current_user()
    if user:
        return redirect(url_for('dashboard'))
    return render_template('index.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        invite_code = request.form.get('invite_code', '').strip()

        if not username or not password or not invite_code:
            flash('所有字段都必须填写', 'error')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 20:
            flash('用户名长度必须在3-20个字符之间', 'error')
            return render_template('register.html')

        if password != confirm:
            flash('两次输入的密码不一致', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('密码长度必须至少6个字符', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'error')
            return render_template('register.html')

        invite = InviteCode.query.filter_by(code=invite_code, used=False).first()
        if not invite:
            flash('邀请码无效或已被使用', 'error')
            return render_template('register.html')

        user = User(username=username, invite_code_used=invite_code)
        user.set_password(password)
        db.session.add(user)

        invite.used = True
        invite.used_by = username
        invite.used_at = datetime.utcnow()
        db.session.commit()

        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('登录成功', 'success')
            next_url = request.args.get('next')
            if next_url:
                return redirect(next_url)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))

        flash('用户名或密码错误', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('已退出登录', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    search = request.args.get('q', '')
    category = request.args.get('category', '')

    query = File.query
    if search:
        query = query.filter(File.original_name.contains(search))
    if category:
        query = query.filter_by(category=category)

    files = query.order_by(File.created_at.desc()).all()
    categories = [c[0] for c in db.session.query(File.category).distinct().all()]

    return render_template('dashboard.html', user=user, files=files,
                           categories=categories, search=search,
                           current_category=category)


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    file.download_count += 1
    db.session.commit()

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        file.stored_name,
        as_attachment=True,
        download_name=file.original_name
    )


# ==================== 后台路由 ====================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username, is_admin=True).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('admin_dashboard'))

        flash('管理员账号或密码错误', 'error')

    return render_template('admin/login.html')


@app.route('/admin')
@admin_required
def admin_dashboard():
    user = get_current_user()
    stats = {
        'users': User.query.filter_by(is_admin=False).count(),
        'files': File.query.count(),
        'total_size': db.session.query(func.sum(File.size)).scalar() or 0,
        'downloads': db.session.query(func.sum(File.download_count)).scalar() or 0,
        'invites_total': InviteCode.query.count(),
        'invites_unused': InviteCode.query.filter_by(used=False).count(),
    }
    recent_files = File.query.order_by(File.created_at.desc()).limit(5).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    return render_template('admin/dashboard.html', user=user, stats=stats,
                           recent_files=recent_files, recent_users=recent_users)


@app.route('/admin/files')
@admin_required
def admin_files():
    user = get_current_user()
    files = File.query.order_by(File.created_at.desc()).all()
    return render_template('admin/files.html', user=user, files=files)


@app.route('/admin/upload', methods=['GET', 'POST'])
@admin_required
def admin_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('请选择文件', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('请选择文件', 'error')
            return redirect(request.url)

        original_name = file.filename
        ext = os.path.splitext(original_name)[1]
        stored_name = uuid.uuid4().hex + ext

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        file.save(filepath)

        size = os.path.getsize(filepath)
        description = request.form.get('description', '')
        category = request.form.get('category', '其他') or '其他'
        version = request.form.get('version', '')

        new_file = File(
            original_name=original_name,
            stored_name=stored_name,
            size=size,
            description=description,
            category=category,
            version=version
        )
        db.session.add(new_file)
        db.session.commit()

        flash(f'文件「{original_name}」上传成功', 'success')
        return redirect(url_for('admin_files'))

    return render_template('admin/upload.html', user=get_current_user())


@app.route('/admin/files/<int:file_id>/delete', methods=['POST'])
@admin_required
def admin_delete_file(file_id):
    file = File.query.get_or_404(file_id)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_name)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(file)
    db.session.commit()
    flash('文件已删除', 'success')
    return redirect(url_for('admin_files'))


@app.route('/admin/files/<int:file_id>/edit', methods=['POST'])
@admin_required
def admin_edit_file(file_id):
    file = File.query.get_or_404(file_id)
    file.description = request.form.get('description', '')
    file.category = request.form.get('category', '其他')
    file.version = request.form.get('version', '')
    db.session.commit()
    flash('文件信息已更新', 'success')
    return redirect(url_for('admin_files'))


@app.route('/admin/users')
@admin_required
def admin_users():
    user = get_current_user()
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', user=user, users=users)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('不能删除管理员账号', 'error')
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash('用户已删除', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/invites', methods=['GET', 'POST'])
@admin_required
def admin_invites():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create':
            custom_code = request.form.get('code', '').strip()
            note = request.form.get('note', '').strip()

            if custom_code:
                if InviteCode.query.filter_by(code=custom_code).first():
                    flash('邀请码已存在', 'error')
                else:
                    invite = InviteCode(code=custom_code, note=note)
                    db.session.add(invite)
                    db.session.commit()
                    flash(f'邀请码「{custom_code}」创建成功', 'success')
            else:
                count = int(request.form.get('count', 1))
                count = min(max(count, 1), 50)
                for _ in range(count):
                    code = uuid.uuid4().hex[:8].upper()
                    while InviteCode.query.filter_by(code=code).first():
                        code = uuid.uuid4().hex[:8].upper()
                    invite = InviteCode(code=code, note=note)
                    db.session.add(invite)
                db.session.commit()
                flash(f'成功生成 {count} 个邀请码', 'success')

        elif action == 'delete':
            invite_id = request.form.get('invite_id')
            invite = InviteCode.query.get_or_404(invite_id)
            if invite.used:
                flash('已使用的邀请码不能删除', 'error')
            else:
                db.session.delete(invite)
                db.session.commit()
                flash('邀请码已删除', 'success')

        return redirect(url_for('admin_invites'))

    user = get_current_user()
    invites = InviteCode.query.order_by(InviteCode.created_at.desc()).all()
    return render_template('admin/invites.html', user=user, invites=invites)


# ==================== 初始化 ====================

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('=' * 50)
            print('  默认管理员账号已创建')
            print('  用户名: admin')
            print('  密码:   admin123')
            print('  请登录后立即修改密码！')
            print('=' * 50)


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
