import hashlib, os, secrets, time, json, base64, binascii
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from argon2 import PasswordHasher
import jwt
from .models import Base, engine, Session, User, Department, Ticket, History, IntegrationEvent, Comment, Notification, ExternalEntity, AuditLog, Attachment, AuthSession, Category, RoutingRule
from .routing import recommend
from .integration import integration_client

SECRET=os.getenv('SESSION_SECRET','')
if len(SECRET)<32: raise RuntimeError('Установите SESSION_SECRET длиной не менее 32 символов')
app=FastAPI(title='MODUS FLOW')
app.add_middleware(CORSMiddleware, allow_origins=[os.getenv('FRONTEND_ORIGIN','http://localhost:8000')], allow_credentials=True, allow_methods=['GET','POST'], allow_headers=['Content-Type','X-CSRF-Token'])
ph=PasswordHasher(); attempts=defaultdict(deque)
def session():
    with Session() as db: yield db
def current(request:Request, db=Depends(session)):
    try:
        payload=jwt.decode(request.cookies.get('session',''), SECRET, algorithms=['HS256'])
        if request.method not in ('GET','HEAD','OPTIONS') and not secrets.compare_digest(request.headers.get('X-CSRF-Token',''), payload['csrf']): raise ValueError()
        saved=db.get(AuthSession,hashlib.sha256(payload['jti'].encode()).hexdigest())
        if not saved or saved.user_id!=int(payload['sub']) or saved.expires_at<datetime.now(timezone.utc).replace(tzinfo=None): raise ValueError()
        user=db.get(User,int(payload['sub']))
        if not user or not user.active: raise ValueError()
        return user
    except Exception: raise HTTPException(401,'Сессия недействительна или истекла')
def roles(user,*allowed):
    if user.role not in allowed: raise HTTPException(403,'Недостаточно прав')
def visible(t,u):
    return u.role=='SUPER_ADMIN' or (u.role=='EMPLOYEE' and t.author_id==u.id) or (u.role=='DEPARTMENT_MANAGER' and t.department_id==u.department_id and t.department_id is not None) or (u.role=='EXECUTOR' and t.executor_id==u.id)
def ticket_or_404(db,tid,user):
    t=db.get(Ticket,tid)
    if not t or not visible(t,user): raise HTTPException(404,'Обращение не найдено')
    return t
def serialize(t):
    return {'id':t.id,'number':f'REQ-{t.id:06}','title':t.title,'description':t.description,'category':t.category,'solution':t.solution,'priority':t.priority,'preferred_department_id':t.preferred_department_id,'anonymous':t.token_hash is not None,'recommendation':t.recommendation,'reason':t.reason,'department_id':t.department_id,'executor_id':t.executor_id,'status':t.status,'result':t.result,'due_at':t.due_at.isoformat() if t.due_at else None,'created_at':t.created_at.isoformat()}
def history(db,t,event): db.add(History(ticket_id=t.id,event=event))
def notify(db,t,message):
    if t.author_id is not None: db.add(Notification(user_id=t.author_id,ticket_id=t.id,message=message))
def detail_data(db,t):
    return serialize(t) | {'history':[{'event':h.event,'created_at':h.created_at.isoformat()} for h in db.scalars(select(History).where(History.ticket_id==t.id).order_by(History.id))], 'comments':[{'id':c.id,'author':c.author_label,'body':c.body,'created_at':c.created_at.isoformat()} for c in db.scalars(select(Comment).where(Comment.ticket_id==t.id).order_by(Comment.id))], 'integration':[{'operation':e.operation,'result':e.result,'ok':e.ok} for e in db.scalars(select(IntegrationEvent).where(IntegrationEvent.ticket_id==t.id).order_by(IntegrationEvent.id))], 'external':[{'id':e.id,'external_id':e.external_id,'number':e.number,'status':e.status,'mode':e.mode} for e in db.scalars(select(ExternalEntity).where(ExternalEntity.ticket_id==t.id))]}
def anonymous_ticket(db,token):
    t=db.scalar(select(Ticket).where(Ticket.token_hash==hashlib.sha256(token.encode()).hexdigest()))
    if not t: raise HTTPException(404,'Обращение не найдено')
    return t
class Login(BaseModel): login:str; password:str
class NewTicket(BaseModel):
    title:str=Field(min_length=3,max_length=200); description:str=Field(min_length=5,max_length=5000); category:str=Field(min_length=1,max_length=100); solution:str=Field(default='',max_length=2000); anonymous:bool=False; priority:str='NORMAL'; preferred_department_id:int | None=None
class Route(BaseModel): department_id:int
class Assign(BaseModel): executor_id:int; due_at:datetime | None=None
class Change(BaseModel): status:str; result:str=Field(default='',max_length=3000)
class Order(BaseModel): item:str=Field(min_length=1,max_length=200); key:str=Field(min_length=8,max_length=100)
class Token(BaseModel): token:str=Field(min_length=20,max_length=200)
class CommentBody(BaseModel): body:str=Field(min_length=1,max_length=3000)
class AnonymousComment(CommentBody,Token): pass
class AnonymousStatus(Token): status:str
class DepartmentInput(BaseModel): name:str=Field(min_length=2,max_length=100); description:str=Field(default='',max_length=1000); active:bool=True
class UserInput(BaseModel): login:str=Field(min_length=3,max_length=100,pattern=r'^[A-Za-z0-9_.-]+$'); password:str=Field(min_length=12,max_length=200); role:str; department_id:int | None=None
class UserUpdate(BaseModel): role:str; department_id:int | None=None; active:bool=True
class FileBody(BaseModel): name:str=Field(min_length=1,max_length=200); content_base64:str=Field(max_length=7_000_000)
class CategoryInput(BaseModel): name:str=Field(min_length=2,max_length=100); active:bool=True
class RuleInput(BaseModel): keyword:str=Field(min_length=2,max_length=100); department_id:int; active:bool=True
@app.middleware('http')
async def headers(request, call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'; response.headers['X-Frame-Options']='DENY'; response.headers['Referrer-Policy']='no-referrer'
    return response
@app.post('/api/login')
def login(data:Login,request:Request,response:Response,db=Depends(session)):
    key=request.client.host if request.client else 'unknown'; q=attempts[key]; now=time.monotonic()
    while q and q[0]<now-60: q.popleft()
    if len(q)>=10: raise HTTPException(429,'Слишком много попыток')
    q.append(now); user=db.scalar(select(User).where(User.login==data.login))
    try: valid=user is not None and user.active and ph.verify(user.password_hash,data.password)
    except Exception: valid=False
    if not valid: raise HTTPException(401,'Неверный логин или пароль')
    csrf=secrets.token_urlsafe(32); jti=secrets.token_urlsafe(32); expires=datetime.now(timezone.utc)+timedelta(hours=8)
    db.add(AuthSession(id=hashlib.sha256(jti.encode()).hexdigest(),user_id=user.id,expires_at=expires.replace(tzinfo=None))); db.commit()
    token=jwt.encode({'sub':str(user.id),'csrf':csrf,'jti':jti,'exp':expires},SECRET,algorithm='HS256')
    response.set_cookie('session',token,httponly=True,samesite='strict',secure=os.getenv('COOKIE_SECURE')=='1',max_age=28800)
    return {'csrf':csrf,'login':user.login,'role':user.role}
@app.get('/api/me')
def me(request:Request,u=Depends(current)):
    payload=jwt.decode(request.cookies['session'],SECRET,algorithms=['HS256']); return {'login':u.login,'role':u.role,'csrf':payload['csrf']}
@app.post('/api/logout')
def logout(request:Request,response:Response,u=Depends(current),db=Depends(session)):
    payload=jwt.decode(request.cookies['session'],SECRET,algorithms=['HS256']); saved=db.get(AuthSession,hashlib.sha256(payload['jti'].encode()).hexdigest())
    if saved: db.delete(saved); db.commit()
    response.delete_cookie('session'); return {'ok':True}
@app.get('/api/departments')
def departments(u=Depends(current),db=Depends(session)):
    return [{'id':d.id,'name':d.name,'description':d.description,'active':d.active} for d in db.scalars(select(Department)) if d.active or u.role=='SUPER_ADMIN']
@app.get('/api/users')
def users(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER')
    return [{'id':x.id,'login':x.login,'role':x.role,'department_id':x.department_id,'active':x.active} for x in db.scalars(select(User)) if u.role=='SUPER_ADMIN' or x.department_id==u.department_id]
@app.post('/api/tickets')
def create(data:NewTicket,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); raw=secrets.token_urlsafe(32) if data.anonymous else None
    if data.priority not in ('LOW','NORMAL','HIGH','URGENT'): raise HTTPException(400,'Недопустимый приоритет')
    if data.preferred_department_id is not None:
        preferred=db.get(Department,data.preferred_department_id)
        if not preferred or not preferred.active: raise HTTPException(400,'Отдел недоступен')
    text=(data.title+' '+data.description+' '+data.category).lower(); match=None
    for rule in db.scalars(select(RoutingRule).where(RoutingRule.active==True).order_by(RoutingRule.id)):
        dept=db.get(Department,rule.department_id)
        if rule.keyword.lower() in text and dept and dept.active: match=(dept.name,f'Совпадение по правилу «{rule.keyword}»'); break
    configured=db.scalar(select(RoutingRule.id).limit(1)) is not None
    department,reason=match or (('Руководство','Нет совпадения с активными правилами; требуется ручная проверка') if configured else recommend(data.title,data.description,data.category))
    suggested=db.scalar(select(Department).where(Department.name==department,Department.active==True))
    if not suggested: department='Не определён'; reason='Подходящий активный отдел не найден; требуется ручная проверка'
    t=Ticket(title=data.title,description=data.description,category=data.category,solution=data.solution,priority=data.priority,preferred_department_id=data.preferred_department_id,author_id=None if raw else u.id,token_hash=hashlib.sha256(raw.encode()).hexdigest() if raw else None,recommendation=department,reason=reason,status='NEW')
    db.add(t); db.flush(); history(db,t,'Создано обращение'); notify(db,t,'Обращение создано')
    for admin in db.scalars(select(User).where(User.role=='SUPER_ADMIN',User.active==True)): db.add(Notification(user_id=admin.id,ticket_id=t.id,message='Новое обращение ожидает распределения'))
    db.commit()
    return {'ticket':serialize(t),'anonymous_token':raw}
@app.get('/api/tickets')
def tickets(status:str|None=None,category:str|None=None,department_id:int|None=None,priority:str|None=None,from_date:datetime|None=None,to_date:datetime|None=None,integration:bool|None=None,u=Depends(current),db=Depends(session)):
    query=select(Ticket).order_by(Ticket.id.desc())
    if status: query=query.where(Ticket.status==status)
    if category: query=query.where(Ticket.category==category)
    if department_id is not None: query=query.where(Ticket.department_id==department_id)
    if priority: query=query.where(Ticket.priority==priority)
    if from_date: query=query.where(Ticket.created_at>=from_date)
    if to_date: query=query.where(Ticket.created_at<=to_date)
    if integration is not None:
        has_event=select(IntegrationEvent.id).where(IntegrationEvent.ticket_id==Ticket.id).exists()
        query=query.where(has_event if integration else ~has_event)
    return [serialize(t) for t in db.scalars(query) if visible(t,u)]
@app.post('/api/anonymous')
def anonymous(data:Token, u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); return detail_data(db,anonymous_ticket(db,data.token))
@app.post('/api/anonymous/comment')
def anonymous_comment(data:AnonymousComment,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); t=anonymous_ticket(db,data.token)
    db.add(Comment(ticket_id=t.id,author_id=None,author_label='Анонимный автор',body=data.body)); history(db,t,'Получен ответ анонимного автора')
    if t.status=='NEEDS_INFO': t.status='PENDING_ROUTING' if t.department_id is None else 'IN_PROGRESS'; history(db,t,f'Статус: {t.status}')
    db.commit(); return detail_data(db,t)
@app.post('/api/anonymous/status')
def anonymous_status(data:AnonymousStatus,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); t=anonymous_ticket(db,data.token)
    if t.status!='RESOLVED' or data.status not in ('REOPENED','CLOSED'): raise HTTPException(400,'Недопустимый переход статуса')
    t.status=data.status; history(db,t,f'Статус: {t.status}'); db.commit(); return detail_data(db,t)
@app.get('/api/tickets/{tid}')
def detail(tid:int,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u)
    return detail_data(db,t) | {'attachments':[{'id':a.id,'name':a.name,'size':a.size} for a in db.scalars(select(Attachment).where(Attachment.ticket_id==t.id))]}
@app.post('/api/tickets/{tid}/attachments')
def attach(tid:int,data:FileBody,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u)
    if t.token_hash is not None: raise HTTPException(400,'Вложения к анонимным обращениям пока недоступны')
    suffix=Path(data.name.replace('\\','/')).suffix.lower()
    if suffix not in ('.png','.jpg','.jpeg','.pdf','.txt'): raise HTTPException(400,'Разрешены PNG, JPEG, PDF и TXT')
    try: content=base64.b64decode(data.content_base64,validate=True)
    except (ValueError,binascii.Error): raise HTTPException(400,'Некорректный файл')
    if not content or len(content)>5*1024*1024: raise HTTPException(400,'Размер файла должен быть не более 5 МБ')
    if (suffix=='.pdf' and not content.startswith(b'%PDF-')) or (suffix=='.png' and not content.startswith(b'\x89PNG\r\n\x1a\n')) or (suffix in ('.jpg','.jpeg') and not content.startswith(b'\xff\xd8\xff')) or (suffix=='.txt' and b'\x00' in content): raise HTTPException(400,'Формат файла не соответствует расширению')
    folder=Path(os.getenv('UPLOAD_DIR','uploads')); folder.mkdir(parents=True,exist_ok=True); key=secrets.token_hex(24)+suffix
    name=Path(data.name.replace('\\','/')).name[:200]
    path=folder/key
    try:
        with path.open('xb') as out: out.write(content)
        a=Attachment(ticket_id=t.id,name=name,storage_key=key,size=len(content)); db.add(a); history(db,t,'Добавлено вложение'); db.commit()
    except Exception:
        path.unlink(missing_ok=True); raise
    return {'id':a.id,'name':a.name,'size':a.size}
@app.get('/api/tickets/{tid}/attachments/{aid}')
def download(tid:int,aid:int,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u); a=db.get(Attachment,aid)
    if not a or a.ticket_id!=t.id: raise HTTPException(404,'Вложение не найдено')
    path=Path(os.getenv('UPLOAD_DIR','uploads'))/a.storage_key
    if not path.is_file(): raise HTTPException(404,'Файл не найден')
    return FileResponse(path,media_type='application/octet-stream',filename=a.name,headers={'X-Content-Type-Options':'nosniff'})
@app.post('/api/tickets/{tid}/comments')
def comment(tid:int,data:CommentBody,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u)
    db.add(Comment(ticket_id=t.id,author_id=u.id,author_label=u.login,body=data.body)); history(db,t,'Добавлен комментарий'); notify(db,t,'Добавлен комментарий')
    if u.role=='EMPLOYEE' and t.status=='NEEDS_INFO': t.status='PENDING_ROUTING' if t.department_id is None else 'IN_PROGRESS'; history(db,t,f'Статус: {t.status}')
    db.commit(); return detail_data(db,t)
@app.post('/api/tickets/{tid}/route')
def route(tid:int,data:Route,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); t=ticket_or_404(db,tid,u); d=db.get(Department,data.department_id)
    if not d or not d.active: raise HTTPException(400,'Отдел недоступен')
    if t.status not in ('NEW','PENDING_ROUTING','ASSIGNED','REOPENED'): raise HTTPException(400,'Недопустимый переход')
    t.department_id=d.id; t.executor_id=None; t.status='ASSIGNED'; history(db,t,f'Назначен отдел: {d.name}'); db.add(AuditLog(actor_id=u.id,action=f'Назначен отдел для REQ-{t.id:06}')); notify(db,t,'Обращение распределено')
    for manager in db.scalars(select(User).where(User.role=='DEPARTMENT_MANAGER',User.department_id==d.id,User.active==True)): db.add(Notification(user_id=manager.id,ticket_id=t.id,message='Отделу назначено обращение'))
    db.commit(); return serialize(t)
@app.post('/api/tickets/{tid}/assign')
def assign(tid:int,data:Assign,u=Depends(current),db=Depends(session)):
    roles(u,'DEPARTMENT_MANAGER'); t=ticket_or_404(db,tid,u); worker=db.get(User,data.executor_id)
    if t.status!='ASSIGNED' or not worker or not worker.active or worker.role!='EXECUTOR' or worker.department_id!=u.department_id: raise HTTPException(400,'Исполнитель или статус недоступен')
    t.executor_id=worker.id; t.due_at=data.due_at.replace(tzinfo=None) if data.due_at else None; t.status='IN_PROGRESS'; history(db,t,f'Назначен исполнитель: {worker.login}'); notify(db,t,'Назначен исполнитель'); db.add(Notification(user_id=worker.id,ticket_id=t.id,message='Вам назначено обращение')); db.commit(); return serialize(t)
@app.post('/api/tickets/{tid}/status')
def status(tid:int,data:Change,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u)
    allowed={'EXECUTOR':{'IN_PROGRESS':{'NEEDS_INFO','RESOLVED'},'NEEDS_INFO':{'IN_PROGRESS'}},'DEPARTMENT_MANAGER':{'IN_PROGRESS':{'NEEDS_INFO','RESOLVED'},'NEEDS_INFO':{'IN_PROGRESS'}},'EMPLOYEE':{'RESOLVED':{'REOPENED','CLOSED'}},'SUPER_ADMIN':{'NEW':{'REJECTED','NEEDS_INFO'},'RESOLVED':{'CLOSED','REOPENED'},'REOPENED':{'PENDING_ROUTING'}}}
    if data.status not in allowed.get(u.role,{}).get(t.status,set()): raise HTTPException(400,'Недопустимый переход статуса')
    if data.status in ('RESOLVED','REJECTED') and not data.result.strip(): raise HTTPException(400,'Укажите результат или причину')
    t.status=data.status; t.result=data.result or t.result; history(db,t,f'Статус: {data.status}. {data.result}'); notify(db,t,f'Статус обращения: {data.status}'); db.commit(); return serialize(t)
def integrate(db,t,operation,fn):
    try: result=fn(); ok=True
    except Exception: result={'error':'Сервис 1С недоступен или вернул ошибку'}; ok=False
    db.add(IntegrationEvent(ticket_id=t.id,operation=operation,result=json.dumps(result,ensure_ascii=False),ok=ok))
    if not ok:
        for admin in db.scalars(select(User).where(User.role=='SUPER_ADMIN')): db.add(Notification(user_id=admin.id,ticket_id=t.id,message='Ошибка интеграции 1С'))
    db.commit()
    if not ok: raise HTTPException(502,result['error'])
    return result
@app.get('/api/tickets/{tid}/products')
def products(tid:int,q:str='',u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u)
    return integrate(db,t,'Поиск товаров '+os.getenv('INTEGRATION_MODE','MOCK'),lambda:integration_client().get('/products',{'q':q}))
@app.post('/api/tickets/{tid}/orders')
def order(tid:int,data:Order,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u)
    scoped_key=hashlib.sha256(f'{t.id}:{data.key}'.encode()).hexdigest()
    result=integrate(db,t,'Заявка '+os.getenv('INTEGRATION_MODE','MOCK'),lambda:integration_client().create_order({'item':data.item},scoped_key))
    mode=os.getenv('INTEGRATION_MODE','MOCK').upper(); external_id=str(result['id'])
    existing=db.scalar(select(ExternalEntity).where(ExternalEntity.ticket_id==t.id,ExternalEntity.external_id==external_id,ExternalEntity.mode==mode))
    if not existing: db.add(ExternalEntity(ticket_id=t.id,external_id=external_id,number=result['number'],status=result['status'],mode=mode)); db.commit()
    return result
@app.post('/api/tickets/{tid}/orders/{eid}/refresh')
def refresh_order(tid:int,eid:int,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u); entity=db.get(ExternalEntity,eid)
    if not entity or entity.ticket_id!=tid: raise HTTPException(404,'Заявка не найдена')
    if entity.mode!=os.getenv('INTEGRATION_MODE','MOCK').upper(): raise HTTPException(400,'Режим интеграции изменился')
    from urllib.parse import quote
    result=integrate(db,t,'Проверка заявки '+entity.mode,lambda:integration_client().get('/orders/'+quote(entity.external_id,safe=''))); entity.status=result['status']; db.commit(); return result
@app.get('/api/analytics')
def analytics(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); ts=list(db.scalars(select(Ticket))); events=list(db.scalars(select(IntegrationEvent)))
    resolved=[t for t in ts if t.status in ('RESOLVED','CLOSED')]; now=datetime.now(timezone.utc).replace(tzinfo=None)
    categories={}; departments={}
    for t in ts:
        categories[t.category]=categories.get(t.category,0)+1
        name=db.get(Department,t.department_id).name if t.department_id and db.get(Department,t.department_id) else 'Не распределено'; departments[name]=departments.get(name,0)+1
    response_hours=[]; resolution_hours=[]; titles={}
    for t in ts:
        key=' '.join(t.title.lower().split()); titles[key]=titles.get(key,0)+1
        comments=db.scalars(select(Comment).where(Comment.ticket_id==t.id).order_by(Comment.id)).all()
        staff=next((c for c in comments if c.author_id and (person:=db.get(User,c.author_id)) and person.role!='EMPLOYEE'),None)
        if staff: response_hours.append(max(0,(staff.created_at-t.created_at).total_seconds()/3600))
        solved=next((h for h in db.scalars(select(History).where(History.ticket_id==t.id).order_by(History.id)) if h.event.startswith('Статус: RESOLVED')),None)
        if solved: resolution_hours.append(max(0,(solved.created_at-t.created_at).total_seconds()/3600))
    avg=lambda xs:round(sum(xs)/len(xs),2) if xs else None
    return {'total':len(ts),'new':sum(t.status=='NEW' for t in ts),'in_progress':sum(t.status=='IN_PROGRESS' for t in ts),'resolved':len(resolved),'overdue':sum(t.due_at is not None and t.due_at<now and t.status not in ('RESOLVED','CLOSED','REJECTED') for t in ts),'completion_rate':round(len(resolved)*100/len(ts),1) if ts else 0,'first_response_hours':avg(response_hours),'resolution_hours':avg(resolution_hours),'categories':categories,'departments':departments,'repeated_titles':{k:v for k,v in titles.items() if v>1},'integration_success':sum(e.ok for e in events),'integration_errors':sum(not e.ok for e in events)}
@app.get('/api/notifications')
def notifications(u=Depends(current),db=Depends(session)):
    if u.role in ('SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'):
        now=datetime.now(timezone.utc).replace(tzinfo=None)
        for t in db.scalars(select(Ticket).where(Ticket.due_at!=None,Ticket.status.not_in(('RESOLVED','CLOSED','REJECTED')))):
            if not visible(t,u) or t.due_at>now+timedelta(days=1): continue
            msg=('Срок просрочен' if t.due_at<now else 'Срок приближается')+f': {t.due_at.isoformat()}'
            if not db.scalar(select(Notification).where(Notification.user_id==u.id,Notification.ticket_id==t.id,Notification.message==msg)):
                db.add(Notification(user_id=u.id,ticket_id=t.id,message=msg))
        db.commit()
    return [{'id':n.id,'ticket_id':n.ticket_id,'message':n.message,'read':n.read,'created_at':n.created_at.isoformat()} for n in db.scalars(select(Notification).where(Notification.user_id==u.id).order_by(Notification.id.desc()).limit(100))]
@app.post('/api/notifications/{nid}/read')
def read_notification(nid:int,u=Depends(current),db=Depends(session)):
    n=db.get(Notification,nid)
    if not n or n.user_id!=u.id: raise HTTPException(404,'Уведомление не найдено')
    n.read=True; db.commit(); return {'ok':True}
@app.post('/api/departments')
def add_department(data:DepartmentInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN')
    if db.scalar(select(Department).where(Department.name==data.name)): raise HTTPException(409,'Отдел уже существует')
    d=Department(**data.model_dump()); db.add(d); db.add(AuditLog(actor_id=u.id,action='Создан отдел '+data.name)); db.commit(); return {'id':d.id}
@app.post('/api/departments/{did}')
def edit_department(did:int,data:DepartmentInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); d=db.get(Department,did)
    if not d: raise HTTPException(404,'Отдел не найден')
    other=db.scalar(select(Department).where(Department.name==data.name,Department.id!=did))
    if other: raise HTTPException(409,'Отдел уже существует')
    d.name=data.name; d.description=data.description; d.active=data.active; db.add(AuditLog(actor_id=u.id,action=f'Изменён отдел {did}')); db.commit(); return {'id':d.id}
@app.post('/api/users')
def add_user(data:UserInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN')
    if data.role not in ('EMPLOYEE','SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'): raise HTTPException(400,'Недопустимая роль')
    if data.department_id is not None:
        dept=db.get(Department,data.department_id)
        if not dept or not dept.active: raise HTTPException(400,'Отдел недоступен')
    if data.role in ('DEPARTMENT_MANAGER','EXECUTOR'):
        d=db.get(Department,data.department_id) if data.department_id else None
        if not d or not d.active: raise HTTPException(400,'Нужен активный отдел')
    if db.scalar(select(User).where(User.login==data.login)): raise HTTPException(409,'Логин занят')
    user=User(login=data.login,password_hash=ph.hash(data.password),role=data.role,department_id=data.department_id); db.add(user); db.add(AuditLog(actor_id=u.id,action='Создан пользователь '+data.login)); db.commit(); return {'id':user.id}
@app.post('/api/users/{uid}')
def edit_user(uid:int,data:UserUpdate,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); target=db.get(User,uid)
    if not target: raise HTTPException(404,'Пользователь не найден')
    if data.role not in ('EMPLOYEE','SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'): raise HTTPException(400,'Недопустимая роль')
    if uid==u.id and (not data.active or data.role!='SUPER_ADMIN'): raise HTTPException(400,'Нельзя снять собственные права администратора')
    if data.department_id is not None:
        dept=db.get(Department,data.department_id)
        if not dept or not dept.active: raise HTTPException(400,'Отдел недоступен')
    if data.role in ('DEPARTMENT_MANAGER','EXECUTOR') and data.department_id is None: raise HTTPException(400,'Нужен активный отдел')
    target.role=data.role; target.department_id=data.department_id; target.active=data.active
    if uid!=u.id:
        for s in db.scalars(select(AuthSession).where(AuthSession.user_id==uid)): db.delete(s)
    db.add(AuditLog(actor_id=u.id,action='Изменён пользователь '+target.login)); db.commit(); return {'id':target.id}
@app.post('/api/similar')
def similar(data:NewTicket,u=Depends(current),db=Depends(session)):
    # Only reveal tickets the caller can already read; anonymous submissions are not linked to the caller.
    import re
    def words(s): return set(re.findall(r'[а-яёa-z0-9]{4,}',s.lower()))
    target=words(data.title+' '+data.description); found=[]
    for t in db.scalars(select(Ticket)):
        if not visible(t,u): continue
        other=words(t.title+' '+t.description); score=len(target & other)/len(target | other) if target | other else 0
        if score>=.2: found.append({'id':t.id,'number':f'REQ-{t.id:06}','title':t.title,'score':round(score,2)})
    return sorted(found,key=lambda item:item['score'],reverse=True)[:5]
@app.get('/api/integration/health')
def integration_health(u=Depends(current)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR')
    try: return {'mode':os.getenv('INTEGRATION_MODE','MOCK').upper(),'service':integration_client().get('/health')}
    except Exception: raise HTTPException(502,'Сервис интеграции недоступен')
@app.get('/api/integration/events')
def integration_events(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); return [{'id':e.id,'ticket_id':e.ticket_id,'operation':e.operation,'ok':e.ok,'created_at':e.created_at.isoformat(),'result':e.result} for e in db.scalars(select(IntegrationEvent).order_by(IntegrationEvent.id.desc()).limit(200))]
@app.get('/api/integration/mock-history')
def mock_history(u=Depends(current)):
    roles(u,'SUPER_ADMIN')
    if os.getenv('INTEGRATION_MODE','MOCK').upper()!='MOCK': raise HTTPException(400,'Доступно только в режиме MOCK')
    try: return integration_client().get('/history')
    except Exception: raise HTTPException(502,'Симулятор недоступен')
@app.get('/api/categories')
def list_categories(u=Depends(current),db=Depends(session)):
    return [{'id':c.id,'name':c.name,'active':c.active} for c in db.scalars(select(Category)) if c.active or u.role=='SUPER_ADMIN']
@app.post('/api/categories')
def add_category(data:CategoryInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN')
    if db.scalar(select(Category).where(Category.name==data.name)): raise HTTPException(409,'Категория уже существует')
    c=Category(**data.model_dump()); db.add(c); db.add(AuditLog(actor_id=u.id,action='Создана категория '+data.name)); db.commit(); return {'id':c.id}
@app.post('/api/categories/{cid}')
def edit_category(cid:int,data:CategoryInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); c=db.get(Category,cid)
    if not c: raise HTTPException(404,'Категория не найдена')
    if db.scalar(select(Category).where(Category.name==data.name,Category.id!=cid)): raise HTTPException(409,'Категория уже существует')
    c.name=data.name; c.active=data.active; db.add(AuditLog(actor_id=u.id,action=f'Изменена категория {cid}')); db.commit(); return {'id':c.id}
@app.get('/api/routing-rules')
def list_rules(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); return [{'id':r.id,'keyword':r.keyword,'department_id':r.department_id,'active':r.active} for r in db.scalars(select(RoutingRule))]
@app.post('/api/routing-rules')
def add_rule(data:RuleInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); dept=db.get(Department,data.department_id)
    if not dept or not dept.active: raise HTTPException(400,'Отдел недоступен')
    if db.scalar(select(RoutingRule).where(RoutingRule.keyword==data.keyword.lower())): raise HTTPException(409,'Правило уже существует')
    r=RoutingRule(keyword=data.keyword.lower(),department_id=data.department_id,active=data.active); db.add(r); db.add(AuditLog(actor_id=u.id,action='Создано правило маршрутизации')); db.commit(); return {'id':r.id}
@app.post('/api/routing-rules/{rid}')
def edit_rule(rid:int,data:RuleInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); r=db.get(RoutingRule,rid); dept=db.get(Department,data.department_id)
    if not r: raise HTTPException(404,'Правило не найдено')
    if not dept or (data.active and not dept.active): raise HTTPException(400,'Отдел недоступен')
    if db.scalar(select(RoutingRule).where(RoutingRule.keyword==data.keyword.lower(),RoutingRule.id!=rid)): raise HTTPException(409,'Правило уже существует')
    r.keyword=data.keyword.lower(); r.department_id=data.department_id; r.active=data.active; db.add(AuditLog(actor_id=u.id,action=f'Изменено правило {rid}')); db.commit(); return {'id':r.id}
frontend_dir='frontend-react/dist' if Path('frontend-react/dist/index.html').exists() else 'frontend'
app.mount('/',StaticFiles(directory=frontend_dir,html=True),name='frontend')
