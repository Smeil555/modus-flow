from datetime import datetime, timezone
from sqlalchemy import create_engine, event, String, Integer, Text, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
import os

engine = create_engine(os.getenv('DATABASE_URL', 'sqlite:///./modus.db'), connect_args={'check_same_thread': False})
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
class Department(Base):
    __tablename__='departments'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
class Ticket(Base):
    __tablename__='tickets'
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String)
    solution: Mapped[str] = mapped_column(Text, default='')
    author_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    token_hash: Mapped[str | None] = mapped_column(String, nullable=True, unique=True)
    recommendation: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(String)
    department_id: Mapped[int | None] = mapped_column(ForeignKey('departments.id'), nullable=True)
    executor_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    status: Mapped[str] = mapped_column(String, default='NEW')
    result: Mapped[str] = mapped_column(Text, default='')
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
