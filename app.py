from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from models import db, User, Message, Report, LoginLog, RecoveryFile, BlockedUser, MutedUser, ChatNickname, send_system_message, Group, GroupMember, ActiveSession, GroupMessageRead, MutedCall
from datetime import datetime, timedelta
import uuid
import os
import json
import secrets
import io
import json as _json
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///textcord.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# ─── Setup token (one-time admin creation URL) ────────────────────────────
SETUP_TOKEN_FILE = os.environ.get('TEXTCORD_SETUP_TOKEN_FILE', '/var/lib/textcord/setup_token')
TEXTCORD_CONF = os.environ.get('TEXTCORD_CONF', '/etc/textcord.conf')

def _read_setup_token():
    try:
        with open(SETUP_TOKEN_FILE, 'r') as f:
            return f.read().strip()
    except Exception:
        return None

def _consume_setup_token():
    try: os.remove(SETUP_TOKEN_FILE)
    except Exception: pass

def _write_conf_kv(key, value):
    try:
        lines = []
        if os.path.isfile(TEXTCORD_CONF):
            with open(TEXTCORD_CONF, 'r') as f:
                lines = f.read().splitlines()
        lines = [l for l in lines if not l.startswith(key + '=')]
        lines.append(f'{key}={value}')
        with open(TEXTCORD_CONF, 'w') as f:
            f.write('\n'.join(lines) + '\n')
    except Exception:
        pass

def _read_conf_kv(key, default=''):
    """Read a KEY=value from TEXTCORD_CONF at request time (no restart needed
    for lookups). Falls back to env var, then default."""
    try:
        if os.path.isfile(TEXTCORD_CONF):
            with open(TEXTCORD_CONF, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(key + '='):
                        return line.split('=', 1)[1].strip()
    except Exception:
        pass
    return os.environ.get(key, default)

def _allow_registration():
    return _read_conf_kv('ALLOW_REGISTRATION', 'no').lower() == 'yes'

def _restart_service_async():
    """Fire-and-forget systemd restart so config changes (ALLOW_REGISTRATION,
    HSTS, …) take effect immediately after the admin flips a toggle."""
    def _do():
        try:
            import time as _t; _t.sleep(0.5)
            subprocess.run(['systemctl', 'restart', 'textcord.service'],
                           check=False, capture_output=True)
        except Exception:
            pass
    try:
        import threading, subprocess
        threading.Thread(target=_do, daemon=True).start()
    except Exception:
        pass

def _valid_setup_token(token):
    stored = _read_setup_token()
    return bool(stored) and bool(token) and secrets.compare_digest(stored, token)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

online_users = {}

def kick_banned_user(user_id):
    socketio.emit('force_logout', {'reason': 'You have been banned.'}, room=f'user_{user_id}')


@app.before_request
def check_ban_on_request():
    if current_user.is_authenticated:
        if current_user.identifier == 'SYSTEM':
            pass
        elif current_user.is_deleted or current_user.is_panic_locked or current_user.check_ban():
            if current_user.id in online_users:
                del online_users[current_user.id]
            # Clean session
            sid = session.get('_session_id')
            if sid:
                s = ActiveSession.query.filter_by(session_id=sid).first()
                if s:
                    db.session.delete(s)
                    db.session.commit()
            logout_user()
            if request.headers.get('Content-Type') == 'application/json' or request.path.startswith('/api/'):
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
            
            # ─── SESSION LIMIT CHECK ───
            active_sessions = ActiveSession.query.filter_by(user_id=user.id).all()
            # Clean stale sessions (no activity for 30 min)
            now = datetime.utcnow()
            valid_sessions = []
            for s in active_sessions:
                if (now - s.last_active).total_seconds() > 1800:
                    db.session.delete(s)
                else:
                    valid_sessions.append(s)
            db.session.commit()
            
            if len(valid_sessions) >= user.max_sessions:
                error = "Session limit reached. If this wasn't you, contact the administrator."
                log.success = False
                db.session.commit()
                return render_template('login.html', error=error)
            
            user.last_active = datetime.utcnow()
            db.session.commit()
            login_user(user)
            
            # Register session
            sid = secrets.token_urlsafe(32)
            session['_session_id'] = sid
            active_s = ActiveSession(user_id=user.id, session_id=sid)
            db.session.add(active_s)
            db.session.commit()
            
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
    return render_template('login.html', error=error,
                           allow_registration=_allow_registration())

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
                        sid = secrets.token_urlsafe(32)
                        session['_session_id'] = sid
                        active_s = ActiveSession(user_id=user.id, session_id=sid)
                        db.session.add(active_s)
                        db.session.commit()
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
    sid = session.get('_session_id')
    if sid:
        s = ActiveSession.query.filter_by(session_id=sid).first()
        if s:
            db.session.delete(s)
            db.session.commit()
    logout_user()
    return redirect(url_for('login'))

# ─── MESSAGES ───

@app.route('/messages')
@login_required
def messages():
    if current_user.must_change_password:
        return redirect(url_for('force_password'))
    # Update session activity
    sid = session.get('_session_id')
    if sid:
        s = ActiveSession.query.filter_by(session_id=sid).first()
        if s:
            s.last_active = datetime.utcnow()
            db.session.commit()
    
    users = User.query.filter(User.id != current_user.id, User.is_deleted == False).all()
    blocked_ids = [b.blocked_id for b in BlockedUser.query.filter_by(blocker_id=current_user.id).all()]
    blocked_by_ids = [b.blocker_id for b in BlockedUser.query.filter_by(blocked_id=current_user.id).all()]
    
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
            'user': u,
            'custom_name': nickname.custom_name if nickname else None,
            'is_blocked': u.id in blocked_ids,
            'blocked_me': u.id in blocked_by_ids,
            'last_message': last_msg
        })
    contacts.sort(key=lambda c: c['last_message'].created_at if c['last_message'] else datetime.min, reverse=True)
    
    # Groups
    my_groups = []
    memberships = GroupMember.query.filter_by(user_id=current_user.id).all()
    for mem in memberships:
        g = mem.group
        last_gmsg = Message.query.filter_by(group_id=g.id).order_by(Message.created_at.desc()).first()
        my_groups.append({
            'group': g,
            'my_role': mem.role,
            'my_nick': mem.nickname,
            'last_message': last_gmsg
        })
    my_groups.sort(key=lambda x: x['last_message'].created_at if x['last_message'] else datetime.min, reverse=True)
    
    return render_template('messages.html', contacts=contacts, groups=my_groups,
                           is_admin=current_user.role == 'admin',
                           ringtone_url=get_default_ringtone_url())

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
        return jsonify({'error': 'Empty message'}), 400
    
    blocked = BlockedUser.query.filter_by(blocker_id=receiver_id, blocked_id=current_user.id).first()
    if blocked:
        return jsonify({'error': 'You are blocked by this user'}), 403
    
    msg = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content,
        reply_to_id=reply_to_id,
        status='delivered'
    )
    db.session.add(msg)
    db.session.commit()
    
    socketio.emit('new_message', {
        'id': msg.id,
        'sender_id': current_user.id,
        'receiver_id': receiver_id,
        'content': content,
        'status': 'delivered',
        'is_system': False,
        'is_mine': False,
        'sender_name': current_user.display_name,
        'sender_first_name': current_user.first_name,
        'sender_last_name': current_user.last_name,
        'sender_nickname': current_user.nickname,
        'reply_to_content': None,
        'reply_to_sender': None,
        'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }, room=f'user_{receiver_id}')
    
    return jsonify({'ok': True, 'id': msg.id})

@app.route('/api/messages/delete', methods=['GET', 'POST'])
@login_required
def delete_message():
    data = request.json
    msg_id = data.get('message_id')
    mode = data.get('mode', 'self')
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
        message_id=msg_id
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/messages/search/<contact_id>')
@login_required
def search_messages(contact_id):
    q = request.args.get('q', '').strip().lower()
    if not q:
        return jsonify([])
    msgs = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).filter(Message.content.ilike(f'%{q}%')).order_by(Message.created_at.desc()).limit(50).all()
    
    return jsonify([{
        'id': m.id,
        'sender_name': m.sender.display_name,
        'content': m.content,
        'created_at': m.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for m in msgs if not m.deleted_for_all])

# ─── GROUP CHAT ───

@app.route('/api/groups/create', methods=['POST'])
@login_required
def create_group():
    data = request.json
    name = data.get('name', '').strip()
    member_ids = data.get('member_ids', [])
    
    if not name:
        return jsonify({'error': 'Group name required'}), 400
    if not member_ids:
        return jsonify({'error': 'Select at least one member'}), 400
    
    group = Group(name=name, creator_id=current_user.id)
    db.session.add(group)
    db.session.flush()
    
    # Add creator as admin
    admin_member = GroupMember(group_id=group.id, user_id=current_user.id, role='admin')
    db.session.add(admin_member)
    
    # Add selected members
    for uid in member_ids:
        if uid != current_user.id:
            mem = GroupMember(group_id=group.id, user_id=uid, role='member')
            db.session.add(mem)
    
    db.session.commit()
    
    # Send system message to group
    sys_msg = Message(
        sender_id=current_user.id,
        group_id=group.id,
        content=f'Group "{name}" created by {current_user.display_name}',
        is_system=True,
        status='delivered'
    )
    db.session.add(sys_msg)
    db.session.commit()
    
    # Notify members
    for uid in member_ids:
        socketio.emit('group_update', {'action': 'created', 'group_id': group.id}, room=f'user_{uid}')
    
    return jsonify({'ok': True, 'group_id': group.id})

@app.route('/api/groups/<group_id>/messages')
@login_required
def get_group_messages(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem:
        return jsonify({'error': 'Not a member'}), 403
    
    msgs = Message.query.filter_by(group_id=group_id).order_by(Message.created_at.asc()).all()
    result = []
    for m in msgs:
        if m.deleted_for_all:
            continue
        
        # Get sender's group nickname
        sender_mem = GroupMember.query.filter_by(group_id=group_id, user_id=m.sender_id).first()
        sender_name = m.sender.display_name
        if sender_mem and sender_mem.nickname:
            sender_name = sender_mem.nickname
        
        reply_content = None
        reply_sender = None
        if m.reply_to and not m.reply_to.deleted_for_all:
            reply_content = m.reply_to.content
            reply_sender_mem = GroupMember.query.filter_by(group_id=group_id, user_id=m.reply_to.sender_id).first()
            reply_sender = m.reply_to.sender.display_name
            if reply_sender_mem and reply_sender_mem.nickname:
                reply_sender = reply_sender_mem.nickname
        
        result.append({
            'id': m.id,
            'sender_id': m.sender_id,
            'content': m.content,
            'status': m.status,
            'is_system': m.is_system,
            'is_mine': m.sender_id == current_user.id,
            'sender_name': sender_name,
            'reply_to_content': reply_content,
            'reply_to_sender': reply_sender,
            'created_at': m.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify(result)

@app.route('/api/groups/<group_id>/send', methods=['POST'])
@login_required
def send_group_message(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem:
        return jsonify({'error': 'Not a member'}), 403
    
    data = request.json
    content = data.get('content', '').strip()
    reply_to_id = data.get('reply_to_id')
    
    if not content:
        return jsonify({'error': 'Empty message'}), 400
    
    sender_name = current_user.display_name
    if mem.nickname:
        sender_name = mem.nickname
    
    msg = Message(
        sender_id=current_user.id,
        group_id=group_id,
        content=content,
        reply_to_id=reply_to_id,
        status='delivered'
    )
    db.session.add(msg)
    db.session.commit()
    
    # Notify all group members except sender
    members = GroupMember.query.filter_by(group_id=group_id).all()
    for m in members:
        if m.user_id != current_user.id:
            socketio.emit('new_group_message', {
                'id': msg.id,
                'group_id': group_id,
                'sender_id': current_user.id,
                'content': content,
                'sender_name': sender_name,
                'sender_first_name': current_user.first_name,
                'sender_last_name': current_user.last_name,
                'sender_nickname': current_user.nickname,
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }, room=f'user_{m.user_id}')
    
    return jsonify({'ok': True, 'id': msg.id})

@app.route('/api/groups/<group_id>/info')
@login_required
def get_group_info(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem:
        return jsonify({'error': 'Not a member'}), 403
    
    group = Group.query.get(group_id)
    members = GroupMember.query.filter_by(group_id=group_id).all()
    
    return jsonify({
        'id': group.id,
        'name': group.name,
        'nickname': group.nickname,
        'creator_id': group.creator_id,
        'my_role': mem.role,
        'my_nick': mem.nickname,
        'members': [{
            'user_id': m.user_id,
            'name': m.user.full_name,
            'nickname': m.nickname,
            'role': m.role,
            'display_name': m.user.display_name
        } for m in members]
    })

@app.route('/api/groups/<group_id>/rename', methods=['POST'])
@login_required
def rename_group(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem or mem.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    data = request.json
    group = Group.query.get(group_id)
    if data.get('name'):
        group.name = data['name']
    if 'nickname' in data:
        group.nickname = data['nickname'] or None
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/groups/<group_id>/add-member', methods=['POST'])
@login_required
def add_group_member(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem or mem.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    data = request.json
    user_id = data.get('user_id')
    existing = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if existing:
        return jsonify({'error': 'Already a member'}), 400
    new_mem = GroupMember(group_id=group_id, user_id=user_id, role='member')
    db.session.add(new_mem)
    db.session.commit()
    user = User.query.get(user_id)
    sys_msg = Message(sender_id=current_user.id, group_id=group_id,
                      content=f'{user.display_name} was added to the group', is_system=True, status='delivered')
    db.session.add(sys_msg)
    db.session.commit()
    socketio.emit('group_update', {'action': 'added', 'group_id': group_id}, room=f'user_{user_id}')
    return jsonify({'ok': True})

@app.route('/api/groups/<group_id>/remove-member', methods=['POST'])
@login_required
def remove_group_member(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem or mem.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    data = request.json
    user_id = data.get('user_id')
    target = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not target:
        return jsonify({'error': 'Not a member'}), 404
    user = User.query.get(user_id)
    db.session.delete(target)
    sys_msg = Message(sender_id=current_user.id, group_id=group_id,
                      content=f'{user.display_name} was removed from the group', is_system=True, status='delivered')
    db.session.add(sys_msg)
    db.session.commit()
    socketio.emit('group_update', {'action': 'removed', 'group_id': group_id}, room=f'user_{user_id}')
    return jsonify({'ok': True})

@app.route('/api/groups/<group_id>/transfer-admin', methods=['POST'])
@login_required
def transfer_group_admin(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem or mem.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    data = request.json
    user_id = data.get('user_id')
    target = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not target:
        return jsonify({'error': 'Not a member'}), 404
    target.role = 'admin'
    mem.role = 'member'
    group = Group.query.get(group_id)
    group.creator_id = user_id
    sys_msg = Message(sender_id=current_user.id, group_id=group_id,
                      content=f'Admin rights transferred to {target.user.display_name}', is_system=True, status='delivered')
    db.session.add(sys_msg)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/groups/<group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem:
        return jsonify({'error': 'Not a member'}), 404
    
    if mem.role == 'admin':
        # Transfer to someone else or delete group
        others = GroupMember.query.filter(GroupMember.group_id == group_id, GroupMember.user_id != current_user.id).first()
        if others:
            others.role = 'admin'
            group = Group.query.get(group_id)
            group.creator_id = others.user_id
        else:
            # Last member, delete group
            group = Group.query.get(group_id)
            db.session.delete(group)
            db.session.commit()
            return jsonify({'ok': True})
    
    sys_msg = Message(sender_id=current_user.id, group_id=group_id,
                      content=f'{current_user.display_name} left the group', is_system=True, status='delivered')
    db.session.add(sys_msg)
    db.session.delete(mem)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/groups/<group_id>/set-nick', methods=['POST'])
@login_required
def set_group_nick(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem:
        return jsonify({'error': 'Not a member'}), 403
    data = request.json
    mem.nickname = data.get('nickname', '').strip() or None
    db.session.commit()
    return jsonify({'ok': True})

# ─── CONTACTS API ───

@app.route('/api/contacts')
@login_required
def api_contacts():
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
            'is_system': u.identifier == 'SYSTEM',
            'is_blocked': u.id in blocked_ids,
            'is_deleted': u.is_deleted,
            'activity_status': u.activity_status(),
            'is_active': u.is_active_now(),
            'last_msg_time': last_msg.created_at.isoformat() if last_msg else None
        })
    contacts.sort(key=lambda c: c['last_msg_time'] or '', reverse=True)
    return jsonify(contacts)

@app.route('/api/unread-counts')
@login_required
def unread_counts():
    from sqlalchemy import func
    counts = db.session.query(Message.sender_id, func.count(Message.id)).filter(
        Message.receiver_id == current_user.id,
        Message.status == 'delivered',
        Message.deleted_for_all == False,
        Message.deleted_by_receiver == False
    ).group_by(Message.sender_id).all()
    return jsonify({sender_id: count for sender_id, count in counts})

@app.route('/api/group-unread-counts')
@login_required
def group_unread_counts():
    from sqlalchemy import func
    memberships = GroupMember.query.filter_by(user_id=current_user.id).all()
    result = {}
    for mem in memberships:
        read_record = GroupMessageRead.query.filter_by(group_id=mem.group_id, user_id=current_user.id).first()
        query = Message.query.filter(
            Message.group_id == mem.group_id,
            Message.sender_id != current_user.id,
            Message.deleted_for_all == False
        )
        if read_record:
            query = query.filter(Message.created_at > read_record.last_read_at)
        count = query.count()
        if count > 0:
            result[mem.group_id] = count
    return jsonify(result)

@app.route('/api/groups/<group_id>/mark-read', methods=['POST'])
@login_required
def mark_group_read(group_id):
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not mem:
        return jsonify({'error': 'Not a member'}), 403
    read_record = GroupMessageRead.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if read_record:
        read_record.last_read_at = datetime.utcnow()
    else:
        read_record = GroupMessageRead(group_id=group_id, user_id=current_user.id)
        db.session.add(read_record)
    db.session.commit()
    return jsonify({'ok': True})

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

@app.route('/api/chat/mute-calls', methods=['POST'])
@login_required
def mute_calls():
    contact_id = request.json.get('contact_id')
    if not MutedCall.query.filter_by(muter_id=current_user.id, muted_id=contact_id).first():
        db.session.add(MutedCall(muter_id=current_user.id, muted_id=contact_id))
        db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chat/unmute-calls', methods=['POST'])
@login_required
def unmute_calls():
    contact_id = request.json.get('contact_id')
    m = MutedCall.query.filter_by(muter_id=current_user.id, muted_id=contact_id).first()
    if m:
        db.session.delete(m)
        db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chat/call-status', methods=['GET'])
@login_required
def call_status():
    contact_id = request.args.get('contact_id')
    muted = MutedCall.query.filter_by(muter_id=current_user.id, muted_id=contact_id).first() is not None
    return jsonify({'call_muted': muted})

@app.route('/api/call/log', methods=['POST'])
@login_required
def log_call():
    """Insert call status as a neutral event inside the DM conversation, not in System TextCord."""
    data = request.json
    contact_id = data.get('contact_id')
    kind = data.get('kind')  # 'ended' | 'missed' | 'declined' | 'failed'
    duration = int(data.get('duration') or 0)
    other = User.query.get(contact_id)
    if not other:
        return jsonify({'error': 'no user'}), 400
    me_name = current_user.full_name
    other_name = other.full_name
    def fmt(sec):
        h = sec // 3600; m = (sec % 3600) // 60; s = sec % 60
        return f"{h:02d}:{m:02d}:{s:02d}"
    if kind == 'ended':
        text = f"Call ended. Duration: {fmt(duration)}"
    elif kind == 'missed':
        text = f"Missed call: {me_name} called {other_name}"
    elif kind == 'declined':
        text = f"Call declined: {me_name} called {other_name}"
    else:
        text = f"Call failed: {me_name} and {other_name}"
    msg = Message(sender_id=current_user.id, receiver_id=contact_id, content=text, is_system=True, status='delivered')
    db.session.add(msg)
    db.session.commit()
    socketio.emit('new_message', {
        'id': msg.id,
        'sender_id': current_user.id,
        'receiver_id': contact_id,
        'content': text,
        'status': 'delivered',
        'is_system': True,
        'is_mine': False,
        'sender_name': current_user.display_name,
        'reply_to_content': None,
        'reply_to_sender': None,
        'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }, room=f'user_{contact_id}')
    return jsonify({'ok': True, 'id': msg.id})

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

@app.route('/api/account/set-max-sessions', methods=['POST'])
@login_required
def set_max_sessions():
    data = request.json
    val = int(data.get('max_sessions', 1))
    if val < 1:
        val = 1
    if val > 3:
        val = 3
    current_user.max_sessions = val
    db.session.commit()
    return jsonify({'ok': True, 'max_sessions': val})

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
        pending_reports=pending_reports, all_users=all_users,
        allow_registration=_allow_registration())

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
        nickname = request.form.get('nickname', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        must_change = 'must_change_password' in request.form
        
        if not identifier or not first_name or not last_name or not password:
            error = "All fields except nickname are required."
        elif User.query.filter_by(identifier=identifier).first():
            error = "Identifier already exists."
        else:
            user = User(
                identifier=identifier,
                first_name=first_name,
                last_name=last_name,
                nickname=nickname if nickname else None,
                role=role,
                must_change_password=must_change
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            send_system_message(user.id, f'Welcome {first_name} {last_name}! Enjoy chatting, and please be respectful!')
            socketio.emit('user_created', {'user_id': user.id, 'name': user.full_name})
            success = f"User '{identifier}' created. Password: {password}"
    return render_template('admin/create_user.html', error=error, success=success)

@app.route('/admin/permissions')
@login_required
def admin_permissions():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    return render_template('admin/permissions.html')

@app.route('/admin/reports')
@login_required
def admin_reports():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('admin/reports.html', reports=reports)

@app.route('/api/admin/report/<report_id>/action', methods=['POST'])
@login_required
def admin_report_action(report_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    action = data.get('action')
    report = Report.query.get(report_id)
    if not report:
        return jsonify({'error': 'Not found'}), 404
    
    if action == 'dismiss':
        report.status = 'dismissed'
    elif action == 'warn':
        report.status = 'warned'
        send_system_message(report.reported_user_id, "You have received a warning from administrators regarding your behavior.")
    elif action == 'ban':
        report.status = 'banned'
        user = User.query.get(report.reported_user_id)
        user.is_banned = True
        user.ban_reason = "Banned due to reported message"
        kick_banned_user(user.id)
    
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/send-system-message', methods=['POST'])
@login_required
def admin_send_system_message():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    target = data.get('target')
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Empty message'}), 400
    
    if target == 'all':
        users = User.query.filter(User.identifier != 'SYSTEM', User.is_deleted == False).all()
        for u in users:
            msg = send_system_message(u.id, content)
            socketio.emit('new_message', {
                'id': msg.id,
                'sender_id': msg.sender_id,
                'content': content,
                'is_system': True,
                'sender_name': 'System TextCord',
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }, room=f'user_{u.id}')
    else:
        msg = send_system_message(target, content)
        socketio.emit('new_message', {
            'id': msg.id,
            'sender_id': msg.sender_id,
            'content': content,
            'is_system': True,
            'sender_name': 'System TextCord',
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }, room=f'user_{target}')
    
    return jsonify({'ok': True})

# ─── SOCKETIO ───

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = True
        join_room(f'user_{current_user.id}')
        current_user.last_active = datetime.utcnow()
        db.session.commit()

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        if current_user.id in online_users:
            del online_users[current_user.id]

@socketio.on('heartbeat')
def handle_heartbeat():
    if current_user.is_authenticated:
        current_user.last_active = datetime.utcnow()
        sid = session.get('_session_id')
        if sid:
            s = ActiveSession.query.filter_by(session_id=sid).first()
            if s:
                s.last_active = datetime.utcnow()
        db.session.commit()

# ─── WebRTC Call Signaling ───
@socketio.on('call_invite')
def call_invite(data):
    if not current_user.is_authenticated:
        return
    target = data.get('target_id')
    if not target:
        return
    # Block check
    if BlockedUser.query.filter_by(blocker_id=target, blocked_id=current_user.id).first():
        emit('call_failed', {'reason': 'You are blocked by this user.'})
        return
    if BlockedUser.query.filter_by(blocker_id=current_user.id, blocked_id=target).first():
        emit('call_failed', {'reason': 'You blocked this user.'})
        return
    secure = bool(data.get('secure'))
    socketio.emit('call_incoming', {
        'from_id': current_user.id,
        'from_name': current_user.full_name,
        'from_nickname': current_user.nickname or '',
        'secure': secure,
    }, room=f'user_{target}')

@socketio.on('call_accept')
def call_accept(data):
    if not current_user.is_authenticated: return
    socketio.emit('call_accepted', {'from_id': current_user.id}, room=f'user_{data.get("target_id")}')

@socketio.on('call_decline')
def call_decline(data):
    if not current_user.is_authenticated: return
    socketio.emit('call_declined', {'from_id': current_user.id}, room=f'user_{data.get("target_id")}')

@socketio.on('call_cancel')
def call_cancel(data):
    if not current_user.is_authenticated: return
    socketio.emit('call_cancelled', {'from_id': current_user.id}, room=f'user_{data.get("target_id")}')

@socketio.on('call_end')
def call_end(data):
    if not current_user.is_authenticated: return
    socketio.emit('call_ended', {'from_id': current_user.id}, room=f'user_{data.get("target_id")}')

@socketio.on('call_signal')
def call_signal(data):
    """Relay WebRTC offer/answer/ice candidates."""
    if not current_user.is_authenticated: return
    socketio.emit('call_signal', {
        'from_id': current_user.id,
        'payload': data.get('payload'),
    }, room=f'user_{data.get("target_id")}')

# ─── Group Call Signaling (text-style mesh) ─────────────────────────────
# In-memory only; calls die with the process. Each entry:
#   group_calls[group_id] = {
#       'call_id': str, 'started_by': uid, 'started_at': datetime,
#       'participants': {uid: {name, nickname}}, 'answered': set(uid),
#   }
group_calls = {}

def _user_display(u):
    if u.nickname:
        return u.nickname
    return f"{u.first_name} {u.last_name}"

def _post_group_system(group_id, content):
    """Insert a system-style message into the group conversation and broadcast it live."""
    system_user = User.query.filter_by(identifier='SYSTEM').first()
    sender_id = system_user.id if system_user else current_user.id
    msg = Message(
        sender_id=sender_id,
        group_id=group_id,
        content=content,
        is_system=True,
        status='delivered',
    )
    db.session.add(msg)
    db.session.commit()
    members = GroupMember.query.filter_by(group_id=group_id).all()
    for m in members:
        socketio.emit('new_group_message', {
            'id': msg.id,
            'group_id': group_id,
            'sender_id': sender_id,
            'content': content,
            'sender_name': 'System',
            'sender_first_name': 'System',
            'sender_last_name': 'TextCord',
            'sender_nickname': None,
            'is_system': True,
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }, room=f'user_{m.user_id}')

def _broadcast_group_call_state(group_id):
    call = group_calls.get(group_id)
    payload = {
        'group_id': group_id,
        'active': bool(call),
        'call_id': call['call_id'] if call else None,
        'started_by': call['started_by'] if call else None,
        'participants': [
            {'user_id': uid, 'display': info['name']}
            for uid, info in (call['participants'].items() if call else [])
        ],
    }
    members = GroupMember.query.filter_by(group_id=group_id).all()
    for m in members:
        socketio.emit('group_call_state', payload, room=f'user_{m.user_id}')

@socketio.on('group_call_start')
def group_call_start(data):
    if not current_user.is_authenticated: return
    gid = data.get('group_id')
    if not gid: return
    mem = GroupMember.query.filter_by(group_id=gid, user_id=current_user.id).first()
    if not mem: return
    if gid in group_calls:
        # Already active — treat as join
        return group_call_join({'group_id': gid})
    call_id = secrets.token_hex(8)
    name = _user_display(current_user)
    group_calls[gid] = {
        'call_id': call_id,
        'started_by': current_user.id,
        'started_at': datetime.utcnow(),
        'participants': {current_user.id: {'name': name}},
        'answered': {current_user.id},
    }
    _post_group_system(gid, f"Group call started by {name}.")
    # Invite all other members
    members = GroupMember.query.filter_by(group_id=gid).all()
    for m in members:
        socketio.emit('group_call_incoming', {
            'group_id': gid,
            'call_id': call_id,
            'started_by': current_user.id,
            'started_by_name': name,
        }, room=f'user_{m.user_id}')
    _broadcast_group_call_state(gid)

@socketio.on('group_call_join')
def group_call_join(data):
    if not current_user.is_authenticated: return
    gid = data.get('group_id')
    call = group_calls.get(gid)
    if not call: 
        emit('group_call_failed', {'group_id': gid, 'reason': 'No active call.'})
        return
    mem = GroupMember.query.filter_by(group_id=gid, user_id=current_user.id).first()
    if not mem: return
    if current_user.id in call['participants']:
        return
    name = _user_display(current_user)
    call['participants'][current_user.id] = {'name': name}
    call['answered'].add(current_user.id)
    _post_group_system(gid, f"{name} joined the call.")
    _broadcast_group_call_state(gid)
    # Tell existing participants to initiate WebRTC offers to the joiner
    for uid in list(call['participants'].keys()):
        if uid != current_user.id:
            socketio.emit('group_call_peer_join', {
                'group_id': gid,
                'user_id': current_user.id,
                'display': name,
            }, room=f'user_{uid}')

@socketio.on('group_call_leave')
def group_call_leave(data):
    if not current_user.is_authenticated: return
    gid = data.get('group_id')
    call = group_calls.get(gid)
    if not call: return
    if current_user.id not in call['participants']: return
    name = call['participants'][current_user.id]['name']
    del call['participants'][current_user.id]
    # Notify remaining peers to drop this peer
    for uid in list(call['participants'].keys()):
        socketio.emit('group_call_peer_leave', {
            'group_id': gid, 'user_id': current_user.id,
        }, room=f'user_{uid}')
    if not call['participants']:
        answered = len(call['answered'])
        if answered <= 1:
            _post_group_system(gid, f"Call ended — no one answered.")
        else:
            _post_group_system(gid, f"Call ended ({answered} answered).")
        del group_calls[gid]
    else:
        _post_group_system(gid, f"{name} left the call.")
    _broadcast_group_call_state(gid)

@socketio.on('group_call_signal')
def group_call_signal(data):
    """Relay WebRTC offer/answer/ice between two specific participants."""
    if not current_user.is_authenticated: return
    gid = data.get('group_id')
    target = data.get('target_id')
    call = group_calls.get(gid)
    if not call or current_user.id not in call['participants'] or target not in call['participants']:
        return
    socketio.emit('group_call_signal', {
        'group_id': gid,
        'from_id': current_user.id,
        'payload': data.get('payload'),
    }, room=f'user_{target}')

@socketio.on('group_call_query')
def group_call_query(data):
    """Client asks for the current call state of a group (e.g., on opening it)."""
    if not current_user.is_authenticated: return
    gid = data.get('group_id')
    if not gid: return
    mem = GroupMember.query.filter_by(group_id=gid, user_id=current_user.id).first()
    if not mem: return
    call = group_calls.get(gid)
    emit('group_call_state', {
        'group_id': gid,
        'active': bool(call),
        'call_id': call['call_id'] if call else None,
        'started_by': call['started_by'] if call else None,
        'participants': [
            {'user_id': uid, 'display': info['name']}
            for uid, info in (call['participants'].items() if call else [])
        ],
    })

# ─── INIT ───

def init_db():
    with app.app_context():
        db.create_all()

# ─── RINGTONES (Package 3) ───
RINGTONES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'ringtones')
APP_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_config.json')
ALLOWED_RING_EXT = {'mp3', 'wav'}
MAX_RING_SIZE = 5 * 1024 * 1024  # 5 MB

def _load_app_config():
    try:
        with open(APP_CONFIG_PATH, 'r') as f:
            return _json.load(f)
    except Exception:
        return {}

def _save_app_config(cfg):
    try:
        with open(APP_CONFIG_PATH, 'w') as f:
            _json.dump(cfg, f)
    except Exception:
        pass

def get_default_ringtone_url():
    cfg = _load_app_config()
    name = cfg.get('default_ringtone', '')
    if not name:
        return None
    path = os.path.join(RINGTONES_DIR, name)
    if not os.path.isfile(path):
        return None
    return f"/static/ringtones/{name}"

def _list_ringtones():
    if not os.path.isdir(RINGTONES_DIR):
        os.makedirs(RINGTONES_DIR, exist_ok=True)
    return sorted([f for f in os.listdir(RINGTONES_DIR) if f.rsplit('.', 1)[-1].lower() in ALLOWED_RING_EXT])

def _audio_duration_seconds(path):
    """Return duration in seconds or None. Tries ffprobe, then mutagen."""
    try:
        import subprocess
        r = subprocess.run(
            ['ffprobe','-v','error','-show_entries','format=duration',
             '-of','default=noprint_wrappers=1:nokey=1', path],
            capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            s = r.stdout.strip()
            if s: return float(s)
    except Exception:
        pass
    try:
        from mutagen import File as MFile
        mf = MFile(path)
        if mf and getattr(mf, 'info', None) and getattr(mf.info, 'length', None):
            return float(mf.info.length)
    except Exception:
        pass
    return None

@app.route('/admin/ringtones')
@login_required
def admin_ringtones():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    cfg = _load_app_config()
    return render_template('admin/ringtones.html',
                           ringtones=_list_ringtones(),
                           default=cfg.get('default_ringtone', ''),
                           msg=request.args.get('msg'),
                           error=request.args.get('error'))

@app.route('/admin/ringtones/upload', methods=['POST'])
@login_required
def admin_ringtones_upload():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    f = request.files.get('file')
    if not f or not f.filename:
        return redirect('/admin/ringtones?error=No+file')
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_RING_EXT:
        return redirect('/admin/ringtones?error=Only+MP3+or+WAV')
    data = f.read()
    if len(data) > MAX_RING_SIZE:
        return redirect('/admin/ringtones?error=File+too+large')
    os.makedirs(RINGTONES_DIR, exist_ok=True)
    safe = secure_filename(f.filename)
    if not safe:
        safe = f"ring_{secrets.token_hex(4)}.{ext}"
    dest = os.path.join(RINGTONES_DIR, safe)
    with open(dest, 'wb') as out:
        out.write(data)
    # Duration check (max 30s). Prefer ffprobe; fallback to mutagen; else accept.
    try:
        dur = _audio_duration_seconds(dest)
        if dur is not None and dur > 30.5:
            try: os.remove(dest)
            except Exception: pass
            return redirect('/admin/ringtones?error=Too+long+(max+30s)')
    except Exception:
        pass
    return redirect('/admin/ringtones?msg=Uploaded')

@app.route('/admin/ringtones/set-default', methods=['POST'])
@login_required
def admin_ringtones_set_default():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    name = request.form.get('name', '').strip()
    if name:
        path = os.path.join(RINGTONES_DIR, secure_filename(name))
        if not os.path.isfile(path):
            return redirect('/admin/ringtones?error=Not+found')
    cfg = _load_app_config()
    cfg['default_ringtone'] = name
    _save_app_config(cfg)
    return redirect('/admin/ringtones?msg=Default+set')

@app.route('/admin/ringtones/delete', methods=['POST'])
@login_required
def admin_ringtones_delete():
    if current_user.role != 'admin':
        return redirect(url_for('messages'))
    name = secure_filename(request.form.get('name', '').strip())
    if not name:
        return redirect('/admin/ringtones?error=Missing+name')
    path = os.path.join(RINGTONES_DIR, name)
    if os.path.isfile(path):
        try: os.remove(path)
        except Exception: pass
    cfg = _load_app_config()
    if cfg.get('default_ringtone') == name:
        cfg['default_ringtone'] = ''
        _save_app_config(cfg)
    return redirect('/admin/ringtones?msg=Deleted')

# ─── One-time admin setup flow (used by the installer) ────────────────────
@app.route('/o/admin/<token>', methods=['GET', 'POST'])
def setup_admin(token):
    if not _valid_setup_token(token):
        return "Setup link invalid or already used.", 404
    # Admin creation is MANDATORY. Never skip — a fresh install has no admin
    # (installer wipes /var/lib/textcord), and re-showing this form after a
    # partial setup keeps the flow deterministic.
    existing_admin = User.query.filter_by(role='admin').first()
    error = None
    if existing_admin:
        # An admin already exists → move on to the registration-choice step.
        return redirect(url_for('setup_register', token=token))
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        first_name = (request.form.get('first_name') or '').strip()
        last_name  = (request.form.get('last_name') or '').strip()
        nickname   = (request.form.get('nickname') or '').strip() or None
        password   = (request.form.get('password') or '').strip()
        create_rec = request.form.get('create_recovery') == 'on'
        if not identifier or not first_name or not last_name or not password:
            error = "All required fields must be filled."
        elif User.query.filter_by(identifier=identifier).first():
            error = "Identifier already taken."
        else:
            u = User(identifier=identifier, first_name=first_name,
                     last_name=last_name, nickname=nickname, role='admin')
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            if create_rec:
                try:
                    rf = RecoveryFile(user_id=u.id, code=secrets.token_urlsafe(32),
                                      created_by_admin=False)
                    db.session.add(rf)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            return redirect(url_for('setup_register', token=token))
    return render_template('setup_admin.html', token=token, error=error)

@app.route('/o/admin/<token>/register', methods=['GET', 'POST'])
def setup_register(token):
    if not _valid_setup_token(token):
        return "Setup link invalid or already used.", 404
    # Guard: never allow choosing the registration flag before an admin
    # exists. Someone who guessed the URL suffix must still go through the
    # admin creation step first.
    if not User.query.filter_by(role='admin').first():
        return redirect(url_for('setup_admin', token=token))
    if request.method == 'POST':
        choice = request.form.get('allow_registration', 'no')
        value = 'yes' if choice == 'yes' else 'no'
        _write_conf_kv('ALLOW_REGISTRATION', value)
        _consume_setup_token()
        # The registration flag is only read from /etc/textcord.conf on
        # startup for env-injection; restart so the setting is guaranteed
        # to apply immediately (matches the documented behaviour).
        _restart_service_async()
        return redirect(url_for('login'))
    return render_template('setup_register.html', token=token)

# ─── Self-registration (only enabled when ALLOW_REGISTRATION=yes) ─────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if not _allow_registration():
        return "Registration is disabled on this server.", 404
    if current_user.is_authenticated:
        return redirect(url_for('messages'))
    error = None
    if request.method == 'POST':
        # Re-check on POST too — the flag might have been toggled off between
        # the form render and submission.
        if not _allow_registration():
            return "Registration is disabled on this server.", 404
        identifier = (request.form.get('identifier') or '').strip()
        first_name = (request.form.get('first_name') or '').strip()
        last_name  = (request.form.get('last_name') or '').strip()
        nickname   = (request.form.get('nickname') or '').strip() or None
        password   = (request.form.get('password') or '').strip()
        if not identifier or not first_name or not last_name or not password:
            error = "All required fields must be filled."
        elif identifier.upper() == 'SYSTEM':
            error = "This identifier is reserved."
        elif User.query.filter_by(identifier=identifier).first():
            error = "Identifier already taken."
        else:
            u = User(identifier=identifier, first_name=first_name,
                     last_name=last_name, nickname=nickname, role='user')
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            try:
                socketio.emit('new_user', {
                    'id': u.id, 'identifier': u.identifier,
                    'display_name': u.display_name, 'full_name': u.full_name,
                })
            except Exception:
                pass
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

# ─── Admin: toggle self-registration at runtime ───────────────────────────
@app.route('/api/admin/registration-toggle', methods=['POST'])
@login_required
def admin_registration_toggle():
    if current_user.role != 'admin':
        return jsonify({'error': 'forbidden'}), 403
    choice = (request.form.get('allow_registration')
              or (request.get_json(silent=True) or {}).get('allow_registration')
              or 'no')
    value = 'yes' if str(choice).lower() == 'yes' else 'no'
    _write_conf_kv('ALLOW_REGISTRATION', value)
    _restart_service_async()
    return jsonify({'ok': True, 'allow_registration': value,
                    'note': 'Service is restarting to apply the change.'})

if __name__ == '__main__':
    init_db()
    socketio.run(
        app,
        host=os.environ.get('TEXTCORD_HOST', '0.0.0.0'),
        port=int(os.environ.get('TEXTCORD_PORT', '5000')),
        allow_unsafe_werkzeug=True,
    )
