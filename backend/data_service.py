from contextlib import contextmanager

from fastapi import HTTPException
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

from .roles import DEPARTMENT_LEADERS, ROLE_CODES
from .models import AuditLog, AuthSession, Department, RoleGrant, User, UserPermission

PERMISSIONS = {
    'analytics.read': 'Просмотр аналитики',
    'audit.read': 'Просмотр журнала действий',
    'data.read': 'Просмотр состояния базы',
    'integration.read': 'Просмотр журнала интеграции',
    'categories.manage': 'Управление категориями и правилами',
    'departments.manage': 'Управление отделами',
}


def permitted(principal, permission):
    return principal.role == 'SUPER_ADMIN' or permission in principal.permissions


def require(principal, permission):
    if not permitted(principal, permission):
        raise HTTPException(403, 'Недостаточно прав')


def revoke_sessions(db, user_id, keep=None):
    statement = delete(AuthSession).where(AuthSession.user_id == user_id)
    if keep is not None:
        statement = statement.where(AuthSession.id != keep)
    db.execute(statement)


@contextmanager
def account_transaction(db, actor):
    # Lock before reading the administrator count or modifying access.
    if db.bind.dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))
    else:
        db.execute(select(User.id).order_by(User.id).with_for_update()).all()
    current = db.get(User, actor.id)
    if not current or not current.active:
        raise HTTPException(403, 'Недостаточно прав')
    if current.role != 'SUPER_ADMIN' and not db.scalar(
        select(RoleGrant.id).where(RoleGrant.user_id == actor.id, RoleGrant.role == 'SUPER_ADMIN').limit(1)
    ):
        raise HTTPException(403, 'Недостаточно прав')
    try:
        yield
        db.flush()
        admin_grants = select(RoleGrant.user_id).where(RoleGrant.role == 'SUPER_ADMIN')
        admin = db.scalar(select(User.id).where(
            User.active.is_(True), (User.role == 'SUPER_ADMIN') | User.id.in_(admin_grants)
        ).limit(1))
        if admin is None:
            raise HTTPException(409, 'Нужен хотя бы один активный главный администратор')
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, 'Конфликт данных аккаунта') from exc


def audit(db, actor, action):
    db.add(AuditLog(actor_id=actor.id, action=action))


def database_status(db):
    dialect = db.bind.dialect.name
    result = {'status': 'ok', 'engine': dialect, 'database': db.bind.url.database}
    if dialect == 'sqlite':
        from pathlib import Path

        result['database'] = Path(result['database']).name
        result['version'] = db.scalar(text('SELECT sqlite_version()'))
    else:
        db.execute(text('SELECT 1'))
    return result


def user_permissions(db, uid):
    return list(db.scalars(select(UserPermission.permission).where(UserPermission.user_id == uid).order_by(UserPermission.permission)))


def validate_membership(db, role, department_id, previous_department=None):
    if role not in ROLE_CODES:
        raise HTTPException(400, 'Недопустимая роль')
    if department_id is not None:
        department = db.get(Department, department_id)
        if not department or (not department.active and department_id != previous_department):
            raise HTTPException(400, 'Отдел недоступен')
    elif role in (*DEPARTMENT_LEADERS, 'EXECUTOR'):
        raise HTTPException(400, 'Нужен активный отдел')


def account(db, uid):
    user = db.get(User, uid)
    if user is None:
        raise HTTPException(404, 'Пользователь не найден')
    return user


def create_account(db, u, data, password_hash):
    with account_transaction(db, u):
        validate_membership(db, data.role, data.department_id)
        if db.scalar(select(User.id).where(User.login == data.login)):
            raise HTTPException(409, 'Логин занят')
        user = User(login=data.login, password_hash=password_hash, role=data.role,
                    department_id=data.department_id)
        db.add(user)
        audit(db, u, f'Создан аккаунт {data.login} ({data.role})')
    return {'id': user.id}


def update_account(db, u, uid, data):
    with account_transaction(db, u):
        target = account(db, uid)
        if uid == u.id and (not data.active or (target.role == 'SUPER_ADMIN' and data.role != 'SUPER_ADMIN')):
            raise HTTPException(400, 'Нельзя снять собственные права администратора')
        validate_membership(db, data.role, data.department_id, target.department_id)
        old_login = target.login
        if data.login is not None:
            target.login = data.login
        if target.role != data.role:
            audit(db, u, f'Роль {old_login}: {target.role} → {data.role}')
        if target.active != data.active:
            audit(db, u, f'{"Разблокирован" if data.active else "Заблокирован"} аккаунт {old_login}')
        target.role, target.department_id, target.active = data.role, data.department_id, data.active
        if uid != u.id:
            revoke_sessions(db, uid)
        audit(db, u, f'Обновлён аккаунт {old_login} (ID {uid}, логин {target.login}, отдел {target.department_id})')
    return {'id': uid}


def reset_account_password(db, u, uid, password_hash):
    with account_transaction(db, u):
        target = account(db, uid)
        target.password_hash = password_hash
        target.must_change_password = False
        revoke_sessions(db, uid)
        audit(db, u, f'Сброшен пароль аккаунта {target.login} (ID {uid})')
    return {'ok': True}


def update_permissions(db, u, uid, data):
    if data.permissions - PERMISSIONS.keys():
        raise HTTPException(400, 'Недопустимое разрешение')
    with account_transaction(db, u):
        target = account(db, uid)
        db.execute(delete(UserPermission).where(UserPermission.user_id == uid))
        db.add_all(UserPermission(user_id=uid, permission=permission) for permission in sorted(data.permissions))
        audit(db, u, f'Изменены разрешения аккаунта {target.login} (ID {uid}): {", ".join(sorted(data.permissions))}')
    return {'ok': True}


def update_grants(db, u, uid, data):
    with account_transaction(db, u):
        target=account(db,uid)
        if uid==u.id: raise HTTPException(403,'Собственные назначения изменять нельзя')
        seen=set()
        for grant in data.grants:
            validate_membership(db, grant.role, grant.department_id)
            if (grant.role,grant.department_id) in seen or (grant.role==target.role and grant.department_id==target.department_id): raise HTTPException(400,'Повторное назначение')
            seen.add((grant.role,grant.department_id))
        for old in db.scalars(select(RoleGrant).where(RoleGrant.user_id==uid, RoleGrant.office.is_(False))): db.delete(old)
        for grant in data.grants: db.add(RoleGrant(user_id=uid,**grant.model_dump()))
        revoke_sessions(db, uid)
        audit(db, u, 'Изменены дополнительные роли '+target.login)
    return {'ok':True}
