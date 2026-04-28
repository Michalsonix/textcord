from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import uuid
import hashlib
import os
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    identifier = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    nickname = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(20), default='user')  # user or admin
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.Text, nullable=True)
    ban_expires = db.Column(db.DateTime, nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)
    is_panic_locked = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    weekly_active_seconds = db.Column(db.Integer, default=0)
    max_sessions = db.Column(db.Integer, default=1)

    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')
    login_logs = db.relationship('LoginLog', backref='user', lazy='dynamic')
    recovery_files = db.relationship('RecoveryFile', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.salt = os.urandom(32).hex()
        self.password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(self.salt), 100000).hex()

    def check_password(self, password):
        if self.password_hash == 'nologin':
            return False
        h = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(self.salt), 100000).hex()
        return h == self.password_hash

    @property
    def display_name(self):
        if self.nickname:
            return self.nickname
        return f"{self.first_name} {self.last_name}"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def is_active_now(self):
        if self.last_active:
            return (datetime.utcnow() - self.last_active).total_seconds() < 300
        return False

    def activity_status(self):
        if self.is_deleted:
            return "Deleted, read-only"
        if self.is_active_now():
            return "Active"
        if self.last_active:
            diff = datetime.utcnow() - self.last_active
            if diff.total_seconds() < 3600:
                return f"Active {int(diff.total_seconds() / 60)}m ago"
            elif diff.total_seconds() < 86400:
                return f"Active {int(diff.total_seconds() / 3600)}h ago"
            else:
                return f"Active {diff.days}d ago"
        return "Offline"

    def check_ban(self):
        if not self.is_banned:
            return False
        if self.ban_expires and datetime.utcnow() > self.ban_expires:
            self.is_banned = False
            self.ban_reason = None
            self.ban_expires = None
            db.session.commit()
            return False
        return True


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    group_id = db.Column(db.String(36), db.ForeignKey('groups.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    reply_to_id = db.Column(db.String(36), db.ForeignKey('messages.id'), nullable=True)
    status = db.Column(db.String(20), default='sent')
    is_system = db.Column(db.Boolean, default=False)
    deleted_by_sender = db.Column(db.Boolean, default=False)
    deleted_by_receiver = db.Column(db.Boolean, default=False)
    deleted_for_all = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    reply_to = db.relationship('Message', remote_side=[id], uselist=False)
    reports = db.relationship('Report', backref='message', lazy='dynamic')


class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(200), nullable=True)
    creator_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    creator = db.relationship('User', foreign_keys=[creator_id])
    members = db.relationship('GroupMember', backref='group', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def display_name(self):
        return self.nickname or self.name


class GroupMember(db.Model):
    __tablename__ = 'group_members'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    group_id = db.Column(db.String(36), db.ForeignKey('groups.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(20), default='member')  # admin or member
    nickname = db.Column(db.String(100), nullable=True)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])


class ActiveSession(db.Model):
    __tablename__ = 'active_sessions'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(200), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])


class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    reporter_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    reported_user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    message_id = db.Column(db.String(36), db.ForeignKey('messages.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    reporter = db.relationship('User', foreign_keys=[reporter_id])
    reported_user = db.relationship('User', foreign_keys=[reported_user_id])


class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RecoveryFile(db.Model):
    __tablename__ = 'recovery_files'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_by_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class BlockedUser(db.Model):
    __tablename__ = 'blocked_users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    blocker_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    blocked_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    blocker = db.relationship('User', foreign_keys=[blocker_id])
    blocked = db.relationship('User', foreign_keys=[blocked_id])


class MutedUser(db.Model):
    __tablename__ = 'muted_users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    muter_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    muted_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ChatNickname(db.Model):
    __tablename__ = 'chat_nicknames'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    target_user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    custom_name = db.Column(db.String(100), nullable=False)


def send_system_message(receiver_id, content):
    system_user = User.query.filter_by(identifier='SYSTEM').first()
    if not system_user:
        system_user = User(
            identifier='SYSTEM',
            first_name='System',
            last_name='TextCord',
            role='system'
        )
        system_user.salt = os.urandom(32).hex()
        system_user.password_hash = 'nologin'
        db.session.add(system_user)
        db.session.commit()
    
    msg = Message(
        sender_id=system_user.id,
        receiver_id=receiver_id,
        content=content,
        is_system=True,
        status='delivered'
    )
    db.session.add(msg)
    db.session.commit()
    return msg


class GroupMessageRead(db.Model):
    __tablename__ = 'group_message_reads'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    group_id = db.Column(db.String(36), db.ForeignKey('groups.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    last_read_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('group_id', 'user_id'),)
