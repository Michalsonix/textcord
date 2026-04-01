from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from models import db, User, Message, Report, LoginLog, RecoveryFile, BlockedUser, MutedUser, ChatNickname, send_system_message
from datetime import datetime, timedelta
import uuid
import os
import json
import secrets
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///textcord.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

online_users = {}

def kick_banned_user(user_id):
    """Emit event to force-disconnect a banned user"""
    socketio.emit('force_logout', {'reason': 'You have been banned.'}, room=f'user_{user_id}')


# ─── BAN CHECK MIDDLEWARE ───
@app.before_request
def check_ban_on_request():
    if current_user.is_authenticated:
        if current_user.identifier == 'SYSTEM':
            pass
        elif current_user.is_deleted or current_user.is_panic_locked or current_user.check_ban():
            if current_user.id in online_users:
                del online_users[current_user.id]
            logout_user()
            if request.headers.get('Content-Type') == 'application/json' or request.path.startswith('/api/'):
                from flask import abort
                return jsonify({'error': 'banned', 'redirect': '/login'}), 403
            return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# ─── AUTH ROUTES ───

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('messages'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('messages'))
    error = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()
        user = User.query.filter_by(identifier=identifier).first()
        
        if user and user.check_password(password):
            log = LoginLog(user_id=user.id, ip_address=request.remote_addr,
                          user_agent=request.headers.get('User-Agent'), success=True)
            db.session.add(log)
            
            if user.is_deleted:
                error = "This account has been deleted."
                log.success = False
                db.session.commit()
                return render_template('login.html', error=error)
            
            if user.is_panic_locked:
                db.session.commit()
                return render_template('blocked.html', reason="Account locked by owner (panic button)", expires="Contact administrator")
            
            if user.check_ban():
                exp = "Never" if not user.ban_expires else user.ban_expires.strftime('%Y-%m-%d %H:%M')
                db.session.commit()
                return render_template('blocked.html', reason=user.ban_reason or "Banned", expires=exp)
            
            user.last_active = datetime.utcnow()
            db.session.commit()
            login_user(user)
            
            if user.must_change_password:
                return redirect(url_for('force_password'))
            
            return redirect(url_for('messages'))
        else:
            if user:
                log = LoginLog(user_id=user.id, ip_address=request.remote_addr,
                              user_agent=request.headers.get('User-Agent'), success=False)
                db.session.add(log)
                db.session.commit()
            error = "Invalid identifier or password."
    return render_template('login.html', error=error)

@app.route('/login/recovery', methods=['GET', 'POST'])
def login_recovery():
    error = None
    success = None
    if request.method == 'POST':
        if 'recovery_file' not in request.files:
            error = "No file uploaded."
        else:
            f = request.files['recovery_file']
            try:
                data = json.loads(f.read().decode('utf-8'))
                token = data.get('token')
                identifier = data.get('identifier')
                rec = RecoveryFile.query.filter_by(token=token, is_used=False).first()
                if rec:
                    user = User.query.get(rec.user_id)
                    if user and user.identifier == identifier:
                        rec.is_used = True
                        user.must_change_password = True
                        new_pass = secrets.token_urlsafe(12)
                        user.set_password(new_pass)
                        db.session.commit()
                        login_user(user)
                        return redirect(url_for('force_password'))
                    else:
                        error = "Invalid recovery file."
                else:
                    error = "Recovery file already used or invalid."
            except:
                error = "Invalid recovery file format."
    return render_template('login_recovery.html', error=error, success=success)

@app.route('/force-password', methods=['GET', 'POST'])
@login_required
def force_password():
    if not current_user.must_change_password:
        return redirect(url_for('messages'))
    error = None
    if request.method == 'POST':
        new_pass = request.form.get('new_password', '').strip()
        if len(new_pass) < 6:
            error = "Password must be at least 6 characters."
        else:
            current_user.set_password(new_pass)
            current_user.must_change_password = False
            db.session.commit()
            return redirect(url_for('messages'))
    return render_template('force_password.html', error=error)

@app.route('/logout')
@login_required
def logout():
    if current_user.id in online_users:
        del online_users[current_user.id]
    logout_user()
    return redirect(url_for('login'))

# ─── MESSAGES ───

@app.route('/messages')
@login_required
def messages():
    if current_user.must_change_password:
        return redirect(url_for('force_password'))
    users = User.query.filter(User.id != current_user.id, User.is_deleted == False).all()
    blocked_ids = [b.blocked_id for b in BlockedUser.query.filter_by(blocker_id=current_user.id).all()]
    blocked_by_ids = [b.blocker_id for b in BlockedUser.query.filter_by(blocked_id=current_user.id).all()]
    
    # Include SYSTEM user if there are system messages for current user
    system_user = User.query.filter_by(identifier='SYSTEM').first()
    
    contacts = []
    for u in users:
        # Skip SYSTEM user if no messages exist for this user
        if u.identifier == 'SYSTEM':
            has_system_msgs = Message.query.filter_by(sender_id=u.id, receiver_id=current_user.id).first()
            if not has_system_msgs:
                continue
        nickname = ChatNickname.query.filter_by(user_id=current_user.id, target_user_id=u.id).first()
        last_msg = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == u.id)) |
            ((Message.sender_id == u.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at.desc()).first()
        contacts.append({
            'user': u,
            'custom_name': nickname.custom_name if nickname else None,
            'is_blocked': u.id in blocked_ids,
            'blocked_me': u.id in blocked_by_ids,
            'last_message': last_msg
        })
    contacts.sort(key=lambda c: c['last_message'].created_at if c['last_message'] else datetime.min, reverse=True)
    return render_template('messages.html', contacts=contacts, is_admin=current_user.role == 'admin')

@app.route('/api/messages/<contact_id>')
@login_required
def get_messages(contact_id):
    msgs = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at.asc()).all()
    
    result = []
    for m in msgs:
        if m.deleted_for_all:
            continue
        if m.sender_id == current_user.id and m.deleted_by_sender:
            continue
        if m.receiver_id == current_user.id and m.deleted_by_receiver:
            continue
        
        reply_content = None
        reply_sender = None
        if m.reply_to and not m.reply_to.deleted_for_all:
            reply_content = m.reply_to.content
            reply_sender = m.reply_to.sender.display_name
        
        result.append({
            'id': m.id,
            'sender_id': m.sender_id,
            'content': m.content,
            'status': m.status,
            'is_system': m.is_system,
            'is_mine': m.sender_id == current_user.id,
            'sender_name': m.sender.display_name,
            'reply_to_content': reply_content,
            'reply_to_sender': reply_sender,
            'created_at': m.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    # Mark as read
    unread = Message.query.filter_by(receiver_id=current_user.id, sender_id=contact_id, status='delivered').all()
    for m in unread:
        m.status = 'read'
    db.session.commit()
    
    return jsonify(result)

@app.route('/api/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    data = request.json
    receiver_id = data.get('receiver_id')
    content = data.get('content', '').strip()
    reply_to_id = data.get('reply_to_id')
    
    if not content or not receiver_id:
        return jsonify({'error': 'Missing data'}), 400
    
    blocked = BlockedUser.query.filter_by(blocker_id=receiver_id, blocked_id=current_user.id).first()
    if blocked:
        return jsonify({'error': 'You are blocked by this user'}), 403
    
    msg = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content,
        reply_to_id=reply_to_id,
        status='sent'
    )
    db.session.add(msg)
    db.session.commit()
    
    msg.status = 'delivered'
    db.session.commit()
    
    socketio.emit('new_message', {
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_name': current_user.display_name,
        'sender_first_name': current_user.first_name,
        'sender_last_name': current_user.last_name,
        'sender_nickname': current_user.nickname,
        'content': msg.content,
        'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'status': msg.status,
        'is_system': False,
        'reply_to_content': msg.reply_to.content if msg.reply_to else None,
        'reply_to_sender': msg.reply_to.sender.display_name if msg.reply_to else None
    }, room=f'user_{receiver_id}')
    
    return jsonify({
        'id': msg.id,
        'status': msg.status,
        'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/messages/delete', methods=['GET', 'POST'])
@login_required
def delete_message():
    data = request.json
    msg_id = data.get('message_id')
    mode = data.get('mode', 'self')  # self, all
    
    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({'error': 'Not found'}), 404
    
    if mode == 'all' and msg.sender_id == current_user.id:
        msg.deleted_for_all = True
    elif msg.sender_id == current_user.id:
        msg.deleted_by_sender = True
    elif msg.receiver_id == current_user.id:
        msg.deleted_by_receiver = True
    
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/messages/report', methods=['GET', 'POST'])
@login_required
def report_message():
    data = request.json
    msg_id = data.get('message_id')
    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({'error': 'Not found'}), 404
    
    report = Report(
        reporter_id=current_user.id,
        reported_user_id=msg.sender_id,
        message_id=msg.id
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/messages/search/<contact_id>')
@login_required
def search_messages(contact_id):
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])
    
    msgs = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).filter(
        Message.content.ilike(f'%{q}%'),
        Message.deleted_for_all == False
    ).order_by(Message.created_at.desc()).all()
    
    return jsonify([{
        'id': m.id,
        'content': m.content,
        'sender_name': m.sender.display_name,
        'created_at': m.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for m in msgs])

# ─── CHAT SETTINGS ───

@app.route('/api/chat/delete-history', methods=['GET', 'POST'])
@login_required
def delete_chat_history():
    contact_id = request.json.get('contact_id')
    msgs = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).all()
    for m in msgs:
        if m.sender_id == current_user.id:
            m.deleted_by_sender = True
        else:
            m.deleted_by_receiver = True
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chat/block', methods=['GET', 'POST'])
@login_required
def block_user():
    contact_id = request.json.get('contact_id')
    existing = BlockedUser.query.filter_by(blocker_id=current_user.id, blocked_id=contact_id).first()
    if not existing:
        b = BlockedUser(blocker_id=current_user.id, blocked_id=contact_id)
        db.session.add(b)
        db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chat/unblock', methods=['GET', 'POST'])
@login_required
def unblock_user():
    contact_id = request.json.get('contact_id')
    b = BlockedUser.query.filter_by(blocker_id=current_user.id, blocked_id=contact_id).first()
    if b:
        db.session.delete(b)
        db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chat/mute', methods=['GET', 'POST'])
@login_required
def mute_user():
    contact_id = request.json.get('contact_id')
    existing = MutedUser.query.filter_by(muter_id=current_user.id, muted_id=contact_id).first()
    if not existing:
        m = MutedUser(muter_id=current_user.id, muted_id=contact_id)
        db.session.add(m)
        db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chat/unmute', methods=['GET', 'POST'])
@login_required
def unmute_user():
    contact_id = request.json.get('contact_id')
    m = MutedUser.query.filter_by(muter_id=current_user.id, muted_id=contact_id).first()
    if m:
        db.session.delete(m)
        db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chat/rename', methods=['GET', 'POST'])
@login_required
def rename_contact():
    data = request.json
    contact_id = data.get('contact_id')
    custom_name = data.get('custom_name', '').strip()
    
    existing = ChatNickname.query.filter_by(user_id=current_user.id, target_user_id=contact_id).first()
    if custom_name:
        if existing:
            existing.custom_name = custom_name
        else:
            cn = ChatNickname(user_id=current_user.id, target_user_id=contact_id, custom_name=custom_name)
            db.session.add(cn)
    elif existing:
        db.session.delete(existing)
    db.session.commit()
    return jsonify({'ok': True})

# ─── ACCOUNT SETTINGS ───

@app.route('/account', methods=['GET'])
@login_required
def account_settings():
    recovery_count = RecoveryFile.query.filter_by(user_id=current_user.id, is_used=False, created_by_admin=False).count()
    return render_template('account_settings.html', recovery_count=recovery_count, is_admin=current_user.role == 'admin')

@app.route('/api/account/change-nick', methods=['GET', 'POST'])
@login_required
def change_nick():
    nick = request.json.get('nickname', '').strip()
    current_user.nickname = nick if nick else None
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/account/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    data = request.json
    old_pass = data.get('old_password', '')
    new_pass = data.get('new_password', '')
    if not current_user.check_password(old_pass):
        return jsonify({'error': 'Wrong current password'}), 400
    if len(new_pass) < 6:
        return jsonify({'error': 'Password too short'}), 400
    current_user.set_password(new_pass)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/account/generate-recovery', methods=['GET', 'POST'])
@login_required
def generate_recovery():
    unused = RecoveryFile.query.filter_by(user_id=current_user.id, is_used=False, created_by_admin=False).count()
    if unused >= 3:
        return jsonify({'error': 'Maximum 3 active recovery files. Use or delete one first.'}), 400
    
    token = secrets.token_urlsafe(64)
    rec = RecoveryFile(user_id=current_user.id, token=token)
    db.session.add(rec)
    db.session.commit()
    
    data = json.dumps({
        'identifier': current_user.identifier,
        'token': token,
        'created': datetime.utcnow().isoformat(),
        'warning': 'This file can only be used ONCE to reset your password.'
    }, indent=2)
    
    return send_file(
        io.BytesIO(data.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'textcord_recovery_{current_user.identifier}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.json'
    )

@app.route('/api/account/panic', methods=['GET', 'POST'])
@login_required
def panic_lock():
    confirmed = request.json.get('confirmed', False)
    if not confirmed:
        return jsonify({'error': 'Must confirm'}), 400
    current_user.is_panic_locked = True
    db.session.commit()
    logout_user()
    return jsonify({'ok': True})

@app.route('/api/account/delete', methods=['GET', 'POST'])
@login_required
def delete_account():
    confirmed = request.json.get('confirmed', False)
    if not confirmed:
        return jsonify({'error': 'Must confirm'}), 400
    current_user.is_deleted = True
    db.session.commit()
    logout_user()
    return jsonify({'ok': True})

# ─── ADMIN ───

@app.route('/adminpage')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    
    active_users = User.query.filter(User.last_active > datetime.utcnow() - timedelta(minutes=5), User.role == 'user').count()
    active_admins = User.query.filter(User.last_active > datetime.utcnow() - timedelta(minutes=5), User.role == 'admin').count()
    total_users = User.query.filter_by(role='user').count()
    total_admins = User.query.filter_by(role='admin').count()
    pending_reports = Report.query.filter_by(status='pending').count()
    
    all_users = User.query.filter(User.identifier != 'SYSTEM', User.is_deleted == False).all()
    return render_template('admin/dashboard.html',
        active_users=active_users, active_admins=active_admins,
        total_users=total_users, total_admins=total_admins,
        pending_reports=pending_reports, all_users=all_users)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    users = User.query.filter(User.identifier != 'SYSTEM').order_by(User.last_name).all()
    return render_template('admin/users.html', users=users)

@app.route('/api/admin/user/<user_id>')
@login_required
def admin_get_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    
    login_logs = LoginLog.query.filter_by(user_id=user_id).order_by(LoginLog.created_at.desc()).limit(50).all()
    reports_by = Report.query.filter_by(reporter_id=user_id).all()
    reports_on = Report.query.filter_by(reported_user_id=user_id).all()
    recovery_files = RecoveryFile.query.filter_by(user_id=user_id, is_used=False).all()
    
    return jsonify({
        'id': user.id,
        'identifier': user.identifier,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'nickname': user.nickname,
        'role': user.role,
        'is_banned': user.is_banned,
        'ban_reason': user.ban_reason,
        'ban_expires': user.ban_expires.isoformat() if user.ban_expires else None,
        'is_deleted': user.is_deleted,
        'is_panic_locked': user.is_panic_locked,
        'activity_status': user.activity_status(),
        'last_active': user.last_active.isoformat() if user.last_active else None,
        'login_logs': [{'id': l.id, 'ip': l.ip_address, 'success': l.success, 'date': l.created_at.strftime('%Y-%m-%d %H:%M:%S')} for l in login_logs],
        'reports_by_count': len(reports_by),
        'reports_on_count': len(reports_on),
        'reports_by': [{'id': r.id, 'reported': r.reported_user.display_name, 'message': r.message.content[:100], 'date': r.created_at.strftime('%Y-%m-%d %H:%M:%S')} for r in reports_by],
        'reports_on': [{'id': r.id, 'reporter': r.reporter.display_name, 'message': r.message.content[:100], 'date': r.created_at.strftime('%Y-%m-%d %H:%M:%S')} for r in reports_on],
        'recovery_files': [{'id': rf.id, 'date': rf.created_at.strftime('%Y-%m-%d %H:%M:%S'), 'admin': rf.created_by_admin} for rf in recovery_files]
    })

@app.route('/api/admin/user/<user_id>/ban', methods=['GET', 'POST'])
@login_required
def admin_ban_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    
    ban_type = data.get('type', 'permanent')
    reason = data.get('reason', 'No reason provided')
    
    user.is_banned = True
    user.ban_reason = reason
    if ban_type == 'timed':
        duration = int(data.get('duration', 1))
        unit = data.get('unit', 'h')
        if unit == 's': user.ban_expires = datetime.utcnow() + timedelta(seconds=duration)
        elif unit == 'm': user.ban_expires = datetime.utcnow() + timedelta(minutes=duration)
        elif unit == 'h': user.ban_expires = datetime.utcnow() + timedelta(hours=duration)
        elif unit == 'd': user.ban_expires = datetime.utcnow() + timedelta(days=duration)
        elif unit == 'y': user.ban_expires = datetime.utcnow() + timedelta(days=duration*365)
    else:
        user.ban_expires = None
    
    db.session.commit()
    send_system_message(user.id, f"Your account has been banned. Reason: {reason}")
    kick_banned_user(user.id)
    return jsonify({'ok': True})

@app.route('/api/admin/user/<user_id>/unban', methods=['GET', 'POST'])
@login_required
def admin_unban_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    user.is_banned = False
    user.ban_reason = None
    user.ban_expires = None
    db.session.commit()
    send_system_message(user.id, "Your ban has been lifted.")
    return jsonify({'ok': True})

@app.route('/api/admin/user/<user_id>/reduce-ban', methods=['GET', 'POST'])
@login_required
def admin_reduce_ban(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    user = User.query.get(user_id)
    if not user or not user.is_banned:
        return jsonify({'error': 'Not found or not banned'}), 404
    
    amount = int(data.get('amount', 1))
    unit = data.get('unit', 'h')
    
    if not user.ban_expires:
        return jsonify({'error': 'Cannot reduce permanent ban. Change to timed first.'}), 400
    
    if unit == 's': user.ban_expires -= timedelta(seconds=amount)
    elif unit == 'm': user.ban_expires -= timedelta(minutes=amount)
    elif unit == 'h': user.ban_expires -= timedelta(hours=amount)
    elif unit == 'd': user.ban_expires -= timedelta(days=amount)
    elif unit == 'y': user.ban_expires -= timedelta(days=amount*365)
    
    if user.ban_expires <= datetime.utcnow():
        user.is_banned = False
        user.ban_reason = None
        user.ban_expires = None
    
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/user/<user_id>/change-ban-type', methods=['GET', 'POST'])
@login_required
def admin_change_ban_type(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    user = User.query.get(user_id)
    if not user or not user.is_banned:
        return jsonify({'error': 'Not found or not banned'}), 404
    
    new_type = data.get('type')
    if new_type == 'permanent':
        user.ban_expires = None
    elif new_type == 'timed':
        duration = int(data.get('duration', 24))
        unit = data.get('unit', 'h')
        if unit == 'h': user.ban_expires = datetime.utcnow() + timedelta(hours=duration)
        elif unit == 'd': user.ban_expires = datetime.utcnow() + timedelta(days=duration)
        elif unit == 'm': user.ban_expires = datetime.utcnow() + timedelta(minutes=duration)
    
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/user/<user_id>/change-password', methods=['GET', 'POST'])
@login_required
def admin_change_password(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    
    mode = data.get('mode')
    if mode == 'generate':
        new_pass = secrets.token_urlsafe(12)
        user.set_password(new_pass)
        user.must_change_password = True
        db.session.commit()
        return jsonify({'ok': True, 'generated_password': new_pass})
    elif mode == 'set':
        new_pass = data.get('password', '')
        if len(new_pass) < 6:
            return jsonify({'error': 'Too short'}), 400
        user.set_password(new_pass)
        db.session.commit()
        return jsonify({'ok': True})
    elif mode == 'disable_recovery':
        rec_id = data.get('recovery_id')
        rec = RecoveryFile.query.get(rec_id)
        if rec and rec.user_id == user_id:
            db.session.delete(rec)
            db.session.commit()
        return jsonify({'ok': True})

@app.route('/api/admin/user/<user_id>/generate-recovery', methods=['GET', 'POST'])
@login_required
def admin_generate_recovery(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    
    token = secrets.token_urlsafe(64)
    rec = RecoveryFile(user_id=user_id, token=token, created_by_admin=True)
    db.session.add(rec)
    db.session.commit()
    
    data = json.dumps({
        'identifier': user.identifier,
        'token': token,
        'created': datetime.utcnow().isoformat(),
        'warning': 'This file can only be used ONCE to reset your password.'
    }, indent=2)
    
    return send_file(
        io.BytesIO(data.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'textcord_recovery_{user.identifier}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.json'
    )

@app.route('/api/admin/user/<user_id>/unlock-panic', methods=['GET', 'POST'])
@login_required
def admin_unlock_panic(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    user.is_panic_locked = False
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/delete-log/<log_id>', methods=['DELETE'])
@login_required
def admin_delete_log(log_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    log = LoginLog.query.get(log_id)
    if log:
        db.session.delete(log)
        db.session.commit()
    return jsonify({'ok': True})

# ─── ADMIN PERMISSIONS ───

@app.route('/admin/permissions')
@login_required
def admin_permissions():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    users = User.query.filter(User.identifier != 'SYSTEM').order_by(User.last_name).all()
    return render_template('admin/permissions.html', users=users)

@app.route('/api/admin/user/<user_id>/set-role', methods=['GET', 'POST'])
@login_required
def admin_set_role(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot change your own role'}), 400
    user.role = data.get('role', 'user')
    db.session.commit()
    return jsonify({'ok': True})

# ─── ADMIN REPORTS ───

@app.route('/admin/reports')
@login_required
def admin_reports():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    reports = Report.query.filter_by(status='pending').order_by(Report.created_at.desc()).all()
    return render_template('admin/reports.html', reports=reports)

@app.route('/api/admin/report/<report_id>/action', methods=['GET', 'POST'])
@login_required
def admin_report_action(report_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    report = Report.query.get(report_id)
    if not report:
        return jsonify({'error': 'Not found'}), 404
    
    action = data.get('action')  # dismiss, warn, ban
    
    if action == 'dismiss':
        report.status = 'dismissed'
    elif action == 'warn':
        report.status = 'warned'
        warn_msg = data.get('message', 'You have been warned by an administrator.')
        send_system_message(report.reported_user_id, f"⚠ WARNING: {warn_msg}")
    elif action == 'ban':
        report.status = 'banned'
        user = User.query.get(report.reported_user_id)
        ban_type = data.get('ban_type', 'permanent')
        reason = data.get('reason', 'Reported content violation')
        user.is_banned = True
        user.ban_reason = reason
        if ban_type == 'timed':
            duration = int(data.get('duration', 24))
            unit = data.get('unit', 'h')
            if unit == 'h': user.ban_expires = datetime.utcnow() + timedelta(hours=duration)
            elif unit == 'd': user.ban_expires = datetime.utcnow() + timedelta(days=duration)
            elif unit == 'm': user.ban_expires = datetime.utcnow() + timedelta(minutes=duration)
        send_system_message(report.reported_user_id, f"Your account has been banned. Reason: {reason}")
        kick_banned_user(report.reported_user_id)
    
    db.session.commit()
    return jsonify({'ok': True})

# ─── ADMIN CREATE USER ───

@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    error = None
    success = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        nickname = request.form.get('nickname', '').strip() or None
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        must_change = request.form.get('must_change_password') == 'on'
        
        if not all([identifier, first_name, last_name, password]):
            error = "All required fields must be filled."
        elif User.query.filter_by(identifier=identifier).first():
            error = "Identifier already exists."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        else:
            user = User(
                identifier=identifier,
                first_name=first_name,
                last_name=last_name,
                nickname=nickname,
                role=role,
                must_change_password=must_change
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            send_system_message(user.id, f"Welcome {user.full_name}! Enjoy chatting, and please be respectful!")
            success = f"User {identifier} created successfully."
            # Notify all connected clients about new user
            socketio.emit('user_created', {
                'id': user.id,
                'full_name': user.full_name,
                'nickname': user.nickname,
                'identifier': user.identifier
            })
    
    return render_template('admin/create_user.html', error=error, success=success)

# ─── ADMIN SYSTEM MESSAGE ───

@app.route('/api/admin/system-message', methods=['GET', 'POST'])
@login_required
def admin_system_message():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    target = data.get('target', 'all')
    message = data.get('message', '').strip()
    
    if not message:
        return jsonify({'error': 'Message is empty'}), 400
    
    if target == 'all':
        users = User.query.filter(User.identifier != 'SYSTEM', User.is_deleted == False).all()
        for u in users:
            msg = send_system_message(u.id, message)
            socketio.emit('new_message', {
                'id': msg.id,
                'sender_id': msg.sender_id,
                'sender_name': 'System TextCord',
                'content': msg.content,
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'delivered',
                'is_system': True,
                'reply_to_content': None,
                'reply_to_sender': None
            }, room=f'user_{u.id}')
    else:
        msg = send_system_message(target, message)
        socketio.emit('new_message', {
            'id': msg.id,
            'sender_id': msg.sender_id,
            'sender_name': 'System TextCord',
            'content': msg.content,
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'delivered',
            'is_system': True,
            'reply_to_content': None,
            'reply_to_sender': None
        }, room=f'user_{target}')
    
    return jsonify({'ok': True})

# ─── UNREAD COUNTS ───

@app.route('/api/unread-counts')
@login_required
def unread_counts():
    from sqlalchemy import func
    counts = db.session.query(
        Message.sender_id, func.count(Message.id)
    ).filter(
        Message.receiver_id == current_user.id,
        Message.status.in_(['sent', 'delivered']),
        Message.deleted_for_all == False,
        Message.deleted_by_receiver == False
    ).group_by(Message.sender_id).all()
    
    return jsonify({sender_id: count for sender_id, count in counts})

@app.route('/api/contacts')
@login_required
def get_contacts():
    users = User.query.filter(User.id != current_user.id, User.is_deleted == False).all()
    blocked_ids = [b.blocked_id for b in BlockedUser.query.filter_by(blocker_id=current_user.id).all()]
    
    contacts = []
    for u in users:
        if u.identifier == 'SYSTEM':
            has_system_msgs = Message.query.filter_by(sender_id=u.id, receiver_id=current_user.id).first()
            if not has_system_msgs:
                continue
        nickname = ChatNickname.query.filter_by(user_id=current_user.id, target_user_id=u.id).first()
        last_msg = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == u.id)) |
            ((Message.sender_id == u.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at.desc()).first()
        contacts.append({
            'id': u.id,
            'full_name': u.full_name,
            'nickname': u.nickname,
            'custom_name': nickname.custom_name if nickname else None,
            'is_blocked': u.id in blocked_ids,
            'is_system': u.identifier == 'SYSTEM',
            'is_deleted': u.is_deleted,
            'status': u.activity_status(),
            'is_active': u.is_active_now(),
            'last_message_at': last_msg.created_at.isoformat() if last_msg else None
        })
    contacts.sort(key=lambda c: c['last_message_at'] or '', reverse=True)
    return jsonify(contacts)

# ─── SOCKETIO ───

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        online_users[current_user.id] = True
        current_user.last_active = datetime.utcnow()
        db.session.commit()

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')
        if current_user.id in online_users:
            del online_users[current_user.id]
        current_user.last_active = datetime.utcnow()
        db.session.commit()

@socketio.on('typing')
def handle_typing(data):
    if current_user.is_authenticated:
        emit('user_typing', {'user_id': current_user.id, 'name': current_user.display_name}, room=f'user_{data.get("to")}')

# ─── INIT ───

def init_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
