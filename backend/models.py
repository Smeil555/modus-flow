from datetime import datetime, timezone
from sqlalchemy import create_engine, event, String, Integer, Text, ForeignKey, DateTime, Boolean, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
import os

database_url = os.getenv('DATABASE_URL', 'sqlite:///./modus.db')
engine = create_engine(database_url, connect_args={'check_same_thread': False} if database_url.startswith('sqlite') else {})
@event.listens_for(engine, 'connect')
def foreign_keys(dbapi, _):
    if engine.dialect.name == 'sqlite': dbapi.execute('PRAGMA foreign_keys=ON')
Session = sessionmaker(bind=engine, expire_on_commit=False)
class Base(DeclarativeBase): pass
def now(): return datetime.now(timezone.utc)
class User(Base):
    __tablename__='users'
    id: Mapped[int] = mapped_column(primary_key=True)
    login: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String)
    department_id: Mapped[int | None] = mapped_column(ForeignKey('departments.id'))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
class Department(Base):
    __tablename__='departments'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default='')
class Ticket(Base):
    __tablename__='tickets'
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String)
    solution: Mapped[str] = mapped_column(Text, default='')
    priority: Mapped[str] = mapped_column(String, default='NORMAL')
    preferred_department_id: Mapped[int | None] = mapped_column(ForeignKey('departments.id'), nullable=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    token_hash: Mapped[str | None] = mapped_column(String, nullable=True, unique=True)
    recommendation: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(String)
    department_id: Mapped[int | None] = mapped_column(ForeignKey('departments.id'), nullable=True)
    executor_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    status: Mapped[str] = mapped_column(String, default='NEW')
    result: Mapped[str] = mapped_column(Text, default='')
    implemented: Mapped[bool] = mapped_column(Boolean,default=False)
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
class History(Base):
    __tablename__='ticket_status_history'
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'), index=True)
    event: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
class IntegrationEvent(Base):
    __tablename__='integration_events'
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'), index=True)
    operation: Mapped[str] = mapped_column(String)
    result: Mapped[str] = mapped_column(Text)
    ok: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
class Comment(Base):
    __tablename__='ticket_comments'
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    author_label: Mapped[str] = mapped_column(String)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
class Notification(Base):
    __tablename__='notifications'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'))
    message: Mapped[str] = mapped_column(String)
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
class ExternalEntity(Base):
    __tablename__='external_entities'
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'), index=True)
    external_id: Mapped[str] = mapped_column(String)
    number: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)
class AuditLog(Base):
    __tablename__='audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
class Attachment(Base):
    __tablename__='ticket_attachments'
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'), index=True)
    name: Mapped[str] = mapped_column(String)
    storage_key: Mapped[str] = mapped_column(String, unique=True)
    size: Mapped[int] = mapped_column(Integer)
class AuthSession(Base):
    __tablename__='auth_sessions'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    selected_role: Mapped[str | None] = mapped_column(String, nullable=True)
    selected_department_id: Mapped[int | None] = mapped_column(ForeignKey('departments.id'), nullable=True)
class RoleGrant(Base):
    __tablename__='department_members'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'),index=True)
    role: Mapped[str] = mapped_column(String)
    department_id: Mapped[int | None] = mapped_column(ForeignKey('departments.id'),nullable=True)
class DeadlineReminder(Base):
    __tablename__='deadline_reminders'
    __table_args__=(UniqueConstraint('user_id','ticket_id','due_at','kind',name='uq_deadline_reminder'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'))
    due_at: Mapped[datetime] = mapped_column(DateTime)
    kind: Mapped[str] = mapped_column(String)
class RateLimitBucket(Base):
    __tablename__='rate_limit_buckets'
    key: Mapped[str] = mapped_column(String,primary_key=True)
    period: Mapped[int] = mapped_column(Integer)
    count: Mapped[int] = mapped_column(Integer)
class Role(Base):
    __tablename__='roles'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String,unique=True)
class TicketAssignment(Base):
    __tablename__='ticket_assignments'
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey('tickets.id'),index=True)
    department_id: Mapped[int | None] = mapped_column(ForeignKey('departments.id'),nullable=True)
    executor_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'),nullable=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'),nullable=True)
    event: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime,default=now)
class IntegrationSetting(Base):
    __tablename__='integration_settings'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String,unique=True)
    value: Mapped[str] = mapped_column(String)
class Category(Base):
    __tablename__='categories'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String,unique=True)
    active: Mapped[bool] = mapped_column(Boolean,default=True)
class RoutingRule(Base):
    __tablename__='routing_rules'
    id: Mapped[int] = mapped_column(primary_key=True)
    keyword: Mapped[str] = mapped_column(String,unique=True)
    department_id: Mapped[int] = mapped_column(ForeignKey('departments.id'))
    active: Mapped[bool] = mapped_column(Boolean,default=True)
