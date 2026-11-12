"""Department routing, visibility, and case transitions for the Data Service."""
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, text

from .data_service import audit
from .models import (
    Appeal, Category, Clarification, Department, History, Notification, Refusal,
    RoleGrant, RoutingIssue, RoutingRule, Ticket, TicketAssignment, User, WorkResult,
)
from .roles import DEPARTMENT_LEADERS, TICKET_REVIEW_ROLES


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def begin_write(db):
    # Authentication reads before the operation starts. Acquire SQLite's write
    # lock before reading the case or any settings used to change it.
    if db.bind.dialect.name == 'sqlite':
        db.rollback()
        db.execute(text('BEGIN IMMEDIATE'))


def active_grants(db, **filters):
    at = utcnow()
    return db.scalars(select(RoleGrant).filter_by(**filters).where(
        or_(RoleGrant.valid_from.is_(None), RoleGrant.valid_from <= at),
        or_(RoleGrant.valid_to.is_(None), RoleGrant.valid_to > at),
    ))


def active_offices(db, department_id):
    return {
        grant.role: grant
        for grant in active_grants(db, department_id=department_id, office=True)
        if (user := db.get(User, grant.user_id)) and user.active
    }


def responsible(db, department_id):
    department = db.get(Department, department_id) if department_id is not None else None
    if not department or not department.active:
        return None
    offices = active_offices(db, department_id)
    return next((offices[role].user_id for role in DEPARTMENT_LEADERS if role in offices), None)


def leads_department(db, user, department_id):
    if user.role not in DEPARTMENT_LEADERS or department_id is None or user.department_id != department_id:
        return False
    return any(active_grants(db, user_id=user.id, department_id=department_id, role=user.role, office=True))


def is_author(ticket, user):
    return ticket.token_hash is None and user.id == ticket.author_id


def assigned(ticket, user):
    return user.role in ('EMPLOYEE', 'EXECUTOR') and ticket.executor_id == user.id


def refusal_for(db, ticket):
    return db.scalar(select(Refusal).where(Refusal.ticket_id == ticket.id).order_by(Refusal.id.desc()).limit(1))


def pending_appeal(db, ticket):
    return db.scalar(select(Appeal).join(Refusal).where(
        Refusal.ticket_id == ticket.id, Appeal.closed_at.is_(None),
    ).order_by(Appeal.id.desc()).limit(1))


def is_administration(db, user_id):
    if user_id is None:
        return False
    user = db.get(User, user_id)
    return bool(user and user.active and (
        user.role in TICKET_REVIEW_ROLES or any(g.role in TICKET_REVIEW_ROLES for g in active_grants(db, user_id=user_id))
    ))


def scope(db, ticket, user):
    if leads_department(db, user, ticket.department_id) or assigned(ticket, user):
        return 'internal'
    if is_author(ticket, user) or (
        ticket.token_hash is None and leads_department(db, user, ticket.author_department_id)
    ):
        return 'author'
    if user.role in TICKET_REVIEW_ROLES:
        if ticket.status == 'APPEAL':
            appeal = pending_appeal(db, ticket)
            if appeal and appeal.admin_user_id == user.id:
                return 'appeal'
        return 'oversight'
    if user.role == 'SUPER_ADMIN':
        return 'oversight'
    return None


def event(db, ticket, kind, message, *, actor=None, reason=None, origin=None, public=False):
    db.add(History(ticket_id=ticket.id, event_type=kind, event=message, actor_id=actor,
                   reason=reason, origin_status=origin, author_visible=public))


def notify(db, ticket, user_id, message):
    if user_id is not None:
        db.add(Notification(user_id=user_id, ticket_id=ticket.id if ticket else None, message=message))


def notify_administration(db, ticket, message):
    for user in db.scalars(select(User).where(User.active.is_(True))):
        if is_administration(db, user.id) or user.role == 'SUPER_ADMIN':
            notify(db, ticket, user.id, message)


def current_route(db, category_id):
    return db.scalar(select(RoutingRule).where(
        RoutingRule.category_id == category_id, RoutingRule.active.is_(True),
        RoutingRule.valid_to.is_(None),
    ).order_by(RoutingRule.version.desc()).limit(1))


def create_request(db, user, data, token_hash):
    begin_write(db)
    category = db.scalar(select(Category).where(Category.name == data.category, Category.active.is_(True)))
    route = current_route(db, category.id) if category else None
    owner_id = responsible(db, route.department_id) if route else None
    if owner_id is None:
        reason = 'Нет активного маршрута для категории' if not route else 'В принимающем отделе нет действующего ответственного'
        db.add(RoutingIssue(category=category.name if category else 'Неизвестная категория', reason=reason))
        notify_administration(db, None, 'Ошибка маршрутизации: ' + reason)
        db.commit()
        raise HTTPException(409, reason + '. Обращение не создано')
    department = db.get(Department, route.department_id)
    if data.preferred_department_id is not None:
        preferred = db.get(Department, data.preferred_department_id)
        if not preferred or not preferred.active:
            raise HTTPException(400, 'Предполагаемый отдел недоступен')
    ticket = Ticket(
        title=data.title.strip(), description=data.description.strip(), category=category.name,
        category_id=category.id, route_rule_id=route.id, kind=data.kind, solution=data.solution,
        priority=data.priority, preferred_department_id=data.preferred_department_id,
        author_id=None if token_hash else user.id,
        author_department_id=None if token_hash else db.get(User, user.id).department_id,
        token_hash=token_hash, department_id=department.id, owner_id=owner_id,
        recommendation=department.name, reason=f'Маршрут категории, версия {route.version}', status='NEW',
    )
    db.add(ticket)
    db.flush()
    event(db, ticket, 'CREATED', 'Обращение создано', actor=ticket.author_id, public=True)
    event(db, ticket, 'ROUTED', 'Обращение автоматически направлено в отдел', reason=ticket.reason, public=True)
    db.add(TicketAssignment(ticket_id=ticket.id, department_id=department.id, event='ROUTED'))
    notify(db, ticket, owner_id, 'Новое обращение поступило в отдел')
    notify(db, ticket, ticket.author_id, 'Обращение создано')
    db.commit()
    return ticket


def open_clarification(db, ticket):
    return db.scalar(select(Clarification).where(
        Clarification.ticket_id == ticket.id, Clarification.answered_at.is_(None),
    ).order_by(Clarification.id.desc()).limit(1))


def pending_result(db, ticket):
    return db.scalar(select(WorkResult).where(
        WorkResult.ticket_id == ticket.id, WorkResult.confirmed_at.is_(None),
        WorkResult.superseded_at.is_(None),
    ).order_by(WorkResult.id.desc()).limit(1))


def author_actions(db, ticket):
    if ticket.status == 'NEEDS_INFO' and open_clarification(db, ticket):
        return ['answer']
    if ticket.status == 'REJECTED' and refusal_for(db, ticket) and not pending_appeal(db, ticket):
        return ['appeal']
    return []


def actions(db, ticket, user):
    options = author_actions(db, ticket) if is_author(ticket, user) else []
    state = ticket.status
    if leads_department(db, user, ticket.department_id):
        if state == 'NEW':
            options += ['accept', 'redirect']
        elif state == 'ASSIGNED':
            options += ['clarify', 'feedback'] if ticket.kind == 'FEEDBACK' else ['clarify', 'assign', 'refuse']
        elif state == 'IN_PROGRESS':
            options += ['assign', 'return', 'clarify']
            result = pending_result(db, ticket)
            if result and result.submitted_by_user_id != user.id:
                options.append('confirm')
        elif state == 'RESOLVED':
            options.append('close')
        elif state == 'APPEAL':
            appeal = pending_appeal(db, ticket)
            if appeal and appeal.admin_user_id != user.id and not is_author(ticket, user):
                options.append('vote')
    if assigned(ticket, user) and state == 'IN_PROGRESS':
        options += ['clarify', 'submit_result']
    if user.role == 'SUPER_ADMIN' and ticket.route_rule_id is None and ticket.owner_id is None and state == 'NEW':
        options.append('redirect')
    if user.role in TICKET_REVIEW_ROLES and state in ('APPEAL', 'REJECTED') and not is_author(ticket, user):
        appeal = pending_appeal(db, ticket)
        if appeal and appeal.admission_decision == 'PENDING':
            options.append('admit')
        elif appeal and state == 'APPEAL':
            if appeal.admin_user_id == user.id:
                options.append('vote')
            elif not is_administration(db, appeal.admin_user_id) and appeal.manager_user_id != user.id:
                options.append('claim')
    return options


class Action(BaseModel):
    action: Literal[
        'accept', 'redirect', 'assign', 'return', 'clarify', 'answer', 'submit_result',
        'confirm', 'close', 'refuse', 'feedback', 'appeal', 'admit', 'claim', 'vote',
    ]
    reason: str = Field(default='', max_length=5000)
    description: str = Field(default='', max_length=5000)
    department_id: int | None = None
    executor_id: int | None = None
    due_at: datetime | None = None
    decision: Literal['ALLOW', 'DENY', 'REOPEN', 'UPHOLD'] | None = None
    record_version: int | None = Field(default=None, ge=1)


def required_text(value, message):
    if not (value := value.strip()):
        raise HTTPException(400, message)
    return value


def eligible_worker(db, user, department_id):
    if not user or not user.active or department_id is None:
        return False
    roles = ('EMPLOYEE', 'EXECUTOR')
    return (user.department_id == department_id and user.role in roles) or any(
        grant.role in roles for grant in active_grants(db, user_id=user.id, department_id=department_id)
    )


def clear_work(db, ticket, at):
    if result := pending_result(db, ticket):
        result.superseded_at = at
    ticket.executor_id = None
    ticket.due_at = None


def apply_action(db, ticket, user, data, *, via_token=False):
    allowed = author_actions(db, ticket) if via_token else actions(db, ticket, user)
    if data.action not in allowed:
        raise HTTPException(403, 'Действие недоступно в текущем статусе или с текущими правами')
    if data.record_version is not None and data.record_version != ticket.record_version:
        raise HTTPException(409, 'Обращение уже изменилось. Обновите карточку')
    actor = None if via_token else user.id
    at = utcnow()
    old = ticket.status
    reason = data.reason.strip()
    public = True
    message = None
    action = data.action

    if action == 'accept':
        ticket.status = 'ASSIGNED'
        message = 'Обращение принято на рассмотрение'
    elif action == 'redirect':
        reason = required_text(reason, 'Укажите причину перенаправления')
        owner_id = responsible(db, data.department_id)
        if data.department_id == ticket.department_id or owner_id is None:
            raise HTTPException(400, 'Выберите другой отдел с действующим ответственным')
        clear_work(db, ticket, at)
        ticket.department_id, ticket.owner_id, ticket.status = data.department_id, owner_id, 'NEW'
        db.add(TicketAssignment(ticket_id=ticket.id, department_id=ticket.department_id, actor_id=actor, event='ROUTED'))
        message = 'Обращение перенаправлено в другой отдел'
        notify(db, ticket, owner_id, message)
    elif action == 'assign':
        worker = db.get(User, data.executor_id) if data.executor_id is not None else None
        if not eligible_worker(db, worker, ticket.department_id):
            raise HTTPException(400, 'Выберите активного сотрудника принимающего отдела')
        if data.due_at is None or data.due_at.utcoffset() is None:
            raise HTTPException(400, 'Укажите срок и его часовой пояс')
        previous = ticket.executor_id
        due = data.due_at.astimezone(timezone.utc).replace(tzinfo=None)
        if worker.id != previous:
            clear_work(db, ticket, at)
        ticket.executor_id, ticket.due_at, ticket.status = worker.id, due, 'IN_PROGRESS'
        db.add(TicketAssignment(ticket_id=ticket.id, department_id=ticket.department_id, executor_id=worker.id,
                                actor_id=actor, event='ASSIGNED'))
        message = 'Назначение исполнителя и срок сохранены'
        reason = f'Исполнитель: {worker.login}. Срок: {due.isoformat()} UTC'
        notify(db, ticket, worker.id, 'Вам назначено обращение или изменён срок')
    elif action == 'return':
        reason = required_text(reason, 'Укажите причину возврата')
        db.add(TicketAssignment(ticket_id=ticket.id, department_id=ticket.department_id,
                                executor_id=ticket.executor_id, actor_id=actor, event='RETURNED'))
        clear_work(db, ticket, at)
        ticket.status = 'ASSIGNED'
        message = 'Обращение возвращено на рассмотрение'
    elif action == 'clarify':
        reason = required_text(reason, 'Введите вопрос автору')
        db.add(Clarification(ticket_id=ticket.id, asked_by_user_id=actor, origin_status=old, question=reason))
        ticket.status = 'NEEDS_INFO'
        message = 'Запрошено уточнение'
    elif action == 'answer':
        reason = required_text(reason, 'Введите ответ на вопрос')
        clarification = open_clarification(db, ticket)
        clarification.answer, clarification.answered_at = reason, at
        ticket.status = clarification.origin_status
        message = 'Получен ответ автора'
        notify(db, ticket, clarification.asked_by_user_id or ticket.owner_id, message)
    elif action == 'submit_result':
        description = required_text(data.description, 'Опишите выполненную работу')
        reason = required_text(reason, 'Укажите результат выполнения')
        if result := pending_result(db, ticket):
            result.superseded_at = at
        db.add(WorkResult(ticket_id=ticket.id, submitted_by_user_id=actor, description=description, outcome=reason))
        message = 'Исполнитель передал результат на подтверждение'
        public = False
        notify(db, ticket, responsible(db, ticket.department_id), message)
    elif action == 'confirm':
        result = pending_result(db, ticket)
        result.confirmed_by_user_id, result.confirmed_at = actor, at
        ticket.status, ticket.result = 'RESOLVED', result.outcome
        message = 'Результат подтверждён'
    elif action == 'close':
        ticket.status = 'CLOSED'
        message = 'Обращение закрыто'
    elif action == 'feedback':
        ticket.result = required_text(reason, 'Укажите, как обработан отзыв')
        ticket.status = 'CLOSED'
        message = 'Положительный отзыв обработан'
    elif action == 'refuse':
        reason = required_text(reason, 'Укажите мотивированную причину отказа')
        refusal = Refusal(ticket_id=ticket.id, decided_by_user_id=actor, reason=reason)
        db.add(refusal)
        db.flush()
        ticket.status, ticket.result = 'REJECTED', reason
        message = f'Отказ № {refusal.id}'
    elif action == 'appeal':
        objection = required_text(data.description, 'Укажите, с чем вы не согласны')
        reason = required_text(reason, 'Обоснуйте запрос на пересмотр')
        refusal = refusal_for(db, ticket)
        first = db.scalar(select(Appeal.id).where(Appeal.refusal_id == refusal.id).limit(1)) is None
        db.add(Appeal(refusal_id=refusal.id, motivation=f'{objection}\n\n{reason}',
                      admission_decision='ALLOW' if first else 'PENDING'))
        if first:
            ticket.status = 'APPEAL'
        message = 'Запрос принят на пересмотр' if first else 'Повторный запрос ожидает решения о допуске'
        notify_administration(db, ticket, message)
        notify(db, ticket, responsible(db, ticket.department_id), message)
    elif action == 'admit':
        reason = required_text(reason, 'Обоснуйте решение о допуске')
        if data.decision not in ('ALLOW', 'DENY'):
            raise HTTPException(400, 'Выберите решение о допуске')
        appeal = pending_appeal(db, ticket)
        appeal.admitted_by_user_id, appeal.admission_decision, appeal.admission_reason = actor, data.decision, reason
        if data.decision == 'ALLOW':
            appeal.admin_user_id = actor
            ticket.status = 'APPEAL'
            message = 'Повторный пересмотр допущен'
            notify(db, ticket, responsible(db, ticket.department_id), message)
        else:
            appeal.closed_at = at
            message = 'В допуске повторного пересмотра отказано'
    elif action == 'claim':
        appeal = pending_appeal(db, ticket)
        appeal.admin_user_id = actor
        appeal.admin_position = appeal.admin_reason = None
        message, public = 'Представитель администрации подключился к пересмотру', False
    elif action == 'vote':
        appeal = pending_appeal(db, ticket)
        reason = required_text(reason, 'Обоснуйте свою позицию')
        if data.decision not in ('REOPEN', 'UPHOLD'):
            raise HTTPException(400, 'Выберите позицию по отказу')
        if user.role in TICKET_REVIEW_ROLES:
            appeal.admin_user_id, appeal.admin_position, appeal.admin_reason = actor, data.decision, reason
        else:
            appeal.manager_user_id, appeal.manager_position, appeal.manager_reason = actor, data.decision, reason
        event(db, ticket, 'APPEAL_POSITION', f'Позиция по пересмотру: {data.decision}', actor=actor, reason=reason)
        public = False
        message = 'Позиция по пересмотру сохранена'
        if appeal.manager_position == appeal.admin_position and is_administration(db, appeal.admin_user_id):
            appeal.joint_outcome, appeal.closed_at = appeal.manager_position, at
            if appeal.joint_outcome == 'REOPEN':
                ticket.status, ticket.result = 'ASSIGNED', ''
                message = 'По итогам пересмотра рассмотрение возобновлено'
            else:
                ticket.status = 'REJECTED'
                message = 'По итогам пересмотра отказ подтверждён'
            public = True
            reason = f'Руководитель: {appeal.manager_reason}\nАдминистрация: {appeal.admin_reason}'

    ticket.record_version += 1
    event(db, ticket, action.upper(), message, actor=actor, reason=reason or None, origin=old, public=public)
    if public:
        notify(db, ticket, ticket.author_id, message)
    db.commit()
    return ticket


def configure_offices(db, user, department_id, head_id, deputy_id):
    begin_write(db)
    department = db.get(Department, department_id)
    if not department or not department.active:
        raise HTTPException(400, 'Выберите активный отдел')
    if head_id is not None and head_id == deputy_id:
        raise HTTPException(400, 'Назначьте разных сотрудников')
    at = utcnow()
    for role, user_id in zip(DEPARTMENT_LEADERS, (head_id, deputy_id)):
        current = list(active_grants(db, department_id=department_id, role=role, office=True))
        if len(current) == 1 and current[0].user_id == user_id:
            continue
        if user_id is not None:
            person = db.get(User, user_id)
            if not person or not person.active or person.id == user.id or person.role == 'SUPER_ADMIN':
                raise HTTPException(400, 'Выберите другого действующего сотрудника')
            if person.department_id != department_id and not any(
                active_grants(db, user_id=person.id, department_id=department_id)
            ):
                raise HTTPException(400, 'Сотрудник должен относиться к этому отделу')
            db.add(RoleGrant(user_id=user_id, department_id=department_id, role=role, office=True, valid_from=at))
        for previous in current:
            previous.valid_to = at
    db.flush()
    owner_id = responsible(db, department_id)
    if owner_id is not None:
        for ticket in db.scalars(select(Ticket).where(
            Ticket.department_id == department_id, Ticket.status != 'CLOSED',
            or_(Ticket.owner_id.is_(None), Ticket.owner_id != owner_id),
        )):
            ticket.owner_id = owner_id
            ticket.record_version += 1
            event(db, ticket, 'OWNER_CHANGED', 'Ответственный отдела изменён', actor=user.id)
            notify(db, ticket, owner_id, 'Вы назначены ответственным за обращение')
    audit(db, user, f'Назначения отдела {department.name}: руководитель {head_id}, заместитель {deputy_id}')
    db.commit()


def publish_route(db, user, category_id, department_id):
    begin_write(db)
    category = db.get(Category, category_id)
    if not category or not category.active or responsible(db, department_id) is None:
        raise HTTPException(400, 'Нужны активная категория, активный отдел и действующий руководитель или заместитель')
    version = (db.scalar(select(func.max(RoutingRule.version)).where(RoutingRule.category_id == category_id)) or 0) + 1
    at = utcnow()
    if previous := current_route(db, category_id):
        previous.active, previous.valid_to = False, at
    route = RoutingRule(keyword=f'@category:{category_id}:{version}', department_id=department_id,
                        category_id=category_id, version=version, valid_from=at, active=True)
    db.add(route)
    audit(db, user, f'Опубликован маршрут категории {category.name}, версия {version}')
    db.commit()
    return route
