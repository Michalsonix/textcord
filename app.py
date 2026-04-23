from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from models import db, User, Message, Report, LoginLog, RecoveryFile, BlockedUser, MutedUser, ChatNickname, send_system_message, Group, GroupMember, ActiveSession, GroupMessageRead
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
    
    return render_template('messages.html', contacts=contacts, groups=my_groups, is_admin=current_user.role == 'admin')

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

# ─── INIT ───

def init_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    init_db()
    import os as _os
    _host = _os.environ.get('TEXTCORD_HOST', '0.0.0.0')
    _port = int(_os.environ.get('TEXTCORD_PORT', '5000'))
    socketio.run(app, host=_host, port=_port, allow_unsafe_werkzeug=True)
