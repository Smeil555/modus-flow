"""Create due and overdue notifications, without associating anonymous authors."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .models import DeadlineReminder, Department, Notification, RoleGrant, Ticket, User

def generate_reminders(db, now=None):
    now=now or datetime.now(timezone.utc).replace(tzinfo=None)
    created=0
    tickets=list(db.scalars(select(Ticket).where(Ticket.due_at!=None,Ticket.status.not_in(('RESOLVED','CLOSED','REJECTED')),Ticket.due_at<=now+timedelta(days=1))))
    users=list(db.scalars(select(User).where(User.active==True)))
    for ticket in tickets:
        kind='OVERDUE' if ticket.due_at<now else 'DUE_SOON'
        for user in users:
            roles={(user.role,user.department_id)} | {(g.role,g.department_id) for g in db.scalars(select(RoleGrant).where(RoleGrant.user_id==user.id))}
            allowed=(user.id==ticket.author_id or user.id==ticket.executor_id or any(role=='SUPER_ADMIN' or (role=='DEPARTMENT_MANAGER' and dept==ticket.department_id and dept is not None) for role,dept in roles))
            if not allowed: continue
            if db.scalar(select(DeadlineReminder.id).where(DeadlineReminder.user_id==user.id,DeadlineReminder.ticket_id==ticket.id,DeadlineReminder.due_at==ticket.due_at,DeadlineReminder.kind==kind)): continue
            try:
                with db.begin_nested():
                    db.add(DeadlineReminder(user_id=user.id,ticket_id=ticket.id,due_at=ticket.due_at,kind=kind)); db.flush()
                    db.add(Notification(user_id=user.id,ticket_id=ticket.id,message=('Срок просрочен' if kind=='OVERDUE' else 'Срок приближается')+f': {ticket.due_at.isoformat()} UTC'))
                created+=1
            except IntegrityError: pass
    db.commit()
    return created
