"""Upgrade the unversioned schema from the first prototype, keeping a SQLite backup."""
import os, sqlite3
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from backend.models import Base, engine

if engine.dialect.name!='sqlite' or engine.url.database in (None,':memory:'):
    raise SystemExit('Поддерживается только файловая SQLite')
path=Path(engine.url.database)
backup=path.with_name(path.name+'.pre-alembic.bak')
if not path.is_file() or backup.exists(): raise SystemExit('База не найдена или резервная копия уже существует')
inspector=inspect(engine)
if inspector.has_table('alembic_version') or not {'users','departments','tickets','ticket_status_history','integration_events'}.issubset(set(inspector.get_table_names())):
    raise SystemExit('Это не неподписанная база предыдущего прототипа')
with sqlite3.connect(path) as source, sqlite3.connect(backup) as destination: source.backup(destination)
with engine.begin() as conn:
    if 'active' not in {x['name'] for x in inspector.get_columns('users')}: conn.exec_driver_sql('ALTER TABLE users ADD COLUMN active BOOLEAN NOT NULL DEFAULT 1')
    if 'description' not in {x['name'] for x in inspector.get_columns('departments')}: conn.exec_driver_sql("ALTER TABLE departments ADD COLUMN description TEXT NOT NULL DEFAULT ''")
    columns={x['name'] for x in inspector.get_columns('tickets')}
    if 'due_at' not in columns: conn.exec_driver_sql('ALTER TABLE tickets ADD COLUMN due_at DATETIME')
    if 'priority' not in columns: conn.exec_driver_sql("ALTER TABLE tickets ADD COLUMN priority VARCHAR NOT NULL DEFAULT 'NORMAL'")
    if 'implemented' not in columns: conn.exec_driver_sql('ALTER TABLE tickets ADD COLUMN implemented BOOLEAN NOT NULL DEFAULT 0')
    if 'preferred_department_id' not in columns: conn.exec_driver_sql('ALTER TABLE tickets ADD COLUMN preferred_department_id INTEGER REFERENCES departments(id)')
Base.metadata.create_all(engine)
command.stamp(Config('alembic.ini'),'head')
print('База обновлена. Резервная копия:',backup)
