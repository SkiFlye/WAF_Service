from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from database.database import *
from core.waf_engine import RULES

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB макс. размер файла

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Класс для Flask-Login
class LoginUser(UserMixin):
    def __init__(self, user_id, email):
        self.id = user_id
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    user = get_user_by_id(int(user_id))
    if user:
        return LoginUser(user['id'], user['email'])
    return None


# Разрешённые расширения для загрузки файлов
ALLOWED_EXTENSIONS = {'json'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ========== ОСНОВНЫЕ МАРШРУТЫ ==========

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash('Пароли не совпадают')
            return redirect(url_for('register'))

        if get_user_by_email(email):
            flash('Пользователь с таким email уже существует')
            return redirect(url_for('register'))

        api_key = secrets.token_urlsafe(32)
        password_hash = generate_password_hash(password)

        user = create_user(email, password_hash, api_key)
        login_user(LoginUser(user['id'], user['email']))

        flash('Регистрация успешна! Сохраните ваш API-ключ:')
        flash(api_key)
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], password):
            login_user(LoginUser(user['id'], user['email']))
            return redirect(url_for('dashboard'))

        flash('Неверный email или пароль')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    stats = get_user_statistics(current_user.id)
    recent_attacks = get_recent_attacks(current_user.id)
    blocked_ips = get_user_blocked_ips(current_user.id)
    user = get_user_by_id(current_user.id)

    return render_template('dashboard.html',
                           stats=stats,
                           recent_attacks=recent_attacks,
                           blocked_ips=blocked_ips,
                           user=user)


# ========== СТАНДАРТНЫЕ ПРАВИЛА ==========

@app.route('/rules')
@login_required
def rules():
    user_rules = get_user_rules_enabled(current_user.id)
    rules_with_status = []
    for rule in RULES:
        enabled = user_rules.get(str(rule["id"]), True)
        rules_with_status.append({
            "id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "enabled": enabled
        })
    return render_template('rules.html', rules=rules_with_status)


@app.route('/toggle_rule', methods=['POST'])
@login_required
def toggle_rule():
    data = request.json
    rule_id = data.get('rule_id')
    enabled = data.get('enabled')
    set_user_rule_enabled(current_user.id, rule_id, enabled)
    return jsonify({'success': True})


# ========== КАСТОМНЫЕ ПРАВИЛА ==========

@app.route('/custom_rules')
@login_required
def custom_rules():
    """Страница управления кастомными правилами"""
    rules = get_custom_rules(current_user.id)
    return render_template('custom_rules.html', rules=rules)


@app.route('/import_rules', methods=['GET', 'POST'])
@login_required
def import_rules():
    """Страница импорта правил из JSON файла"""
    if request.method == 'POST':
        if 'rules_file' not in request.files:
            flash('Файл не выбран', 'danger')
            return redirect(url_for('import_rules'))

        file = request.files['rules_file']
        if file.filename == '':
            flash('Файл не выбран', 'danger')
            return redirect(url_for('import_rules'))

        if not allowed_file(file.filename):
            flash('Разрешены только JSON файлы', 'danger')
            return redirect(url_for('import_rules'))

        try:
            json_content = file.read().decode('utf-8')
            imported, errors = import_custom_rules_from_json(current_user.id, json_content)

            if imported:
                flash(f'✅ Успешно импортировано {len(imported)} правил', 'success')
                for rule in imported:
                    flash(f'   • {rule["name"]}', 'info')

            if errors:
                for error in errors:
                    flash(f'❌ {error}', 'danger')

        except Exception as e:
            flash(f'Ошибка при импорте: {str(e)}', 'danger')

        return redirect(url_for('custom_rules'))

    return render_template('import_rules.html')


@app.route('/export_rules')
@login_required
def export_rules():
    """Экспорт кастомных правил пользователя в JSON"""
    rules = get_custom_rules(current_user.id)

    export_data = []
    for rule in rules:
        export_data.append({
            'name': rule['name'],
            'pattern': rule['pattern'],
            'target': rule['target'],
            'severity': rule['severity']
        })

    response = Response(
        json.dumps(export_data, indent=4, ensure_ascii=False),
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = 'attachment; filename=waf_rules.json'
    return response


@app.route('/delete_custom_rule/<int:rule_id>', methods=['POST'])
@login_required
def delete_custom_rule_route(rule_id):
    """Удаление кастомного правила"""
    delete_custom_rule(current_user.id, rule_id)
    flash('Правило удалено', 'success')
    return redirect(url_for('custom_rules'))


@app.route('/toggle_custom_rule/<int:rule_id>', methods=['POST'])
@login_required
def toggle_custom_rule_route(rule_id):
    """Включение/выключение кастомного правила"""
    data = request.json
    enabled = data.get('enabled', False)
    toggle_custom_rule(current_user.id, rule_id, enabled)
    return jsonify({'success': True})


# ========== НАСТРОЙКИ ==========

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_user_by_id(current_user.id)

    if request.method == 'POST':
        if 'update_rate_limit' in request.form:
            new_limit = int(request.form['rate_limit'])
            session = Session()
            try:
                db_user = session.query(User).filter(User.id == current_user.id).first()
                if db_user:
                    db_user.rate_limit = new_limit
                    session.commit()
            finally:
                session.close()
            flash('Лимит обновлен')
            return redirect(url_for('settings'))
        elif 'delete_account' in request.form:
            delete_user(current_user.id)
            logout_user()
            flash('Аккаунт удален')
            return redirect(url_for('index'))

    return render_template('settings.html', user=user)


# ========== БЛОКИРОВКИ IP ==========

@app.route('/blocked_ips')
@login_required
def blocked_ips():
    blocked = get_user_blocked_ips(current_user.id)
    return render_template('blocked_ips.html', blocked_ips=blocked)


@app.route('/block_ip_manual', methods=['POST'])
@login_required
def block_ip_manual():
    """Ручная блокировка IP"""
    data = request.json
    ip = data.get('ip')
    duration = data.get('duration', 3600)  # по умолчанию 1 час
    reason = data.get('reason', 'Ручная блокировка')
    if not ip:
        return jsonify({'success': False, 'error': 'IP не указан'})

    from database.database import block_ip as block_ip_bd
    block_ip_bd(current_user.id, ip, duration, reason)
    return jsonify({'success': True})


@app.route('/unblock_ip', methods=['POST'])
@login_required
def unblock_ip():
    data = request.json
    ip = data.get('ip')
    from database.database import unblock_ip as unblock_ip_bd
    unblock_ip_bd(current_user.id, ip)
    return jsonify({'success': True})


@app.route('/api/stats')
@login_required
def api_stats():
    stats = get_user_statistics(current_user.id)
    return jsonify(stats)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)