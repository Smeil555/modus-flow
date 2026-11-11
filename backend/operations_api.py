import hashlib, hmac, os, secrets, time, json, base64, binascii
import io, warnings
from PIL import Image, UnidentifiedImageError
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from dataclasses import dataclass
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from argon2 import PasswordHasher
import jwt
from .models import Base, engine, Session, User, Department, Ticket, History, IntegrationEvent, Comment, Notification, ExternalEntity, AuditLog, Attachment, AuthSession, Category, RoutingRule, RoleGrant, TicketAssignment
from .models import IntegrationSetting
from .data_service import (
    PERMISSIONS, account, account_transaction, audit, create_account, database_status,
    permitted, require, reset_account_password, revoke_sessions, update_account,
    update_grants, update_permissions, user_permissions,
)
from .roles import TICKET_REVIEW_ROLES
from .routing import recommend
from .integration import integration_client, create_checked_order, get_checked_order

SECRET=os.getenv('SESSION_SECRET','')
if len(SECRET)<32: raise RuntimeError('Установите SESSION_SECRET длиной не менее 32 символов')
app=FastAPI(title='MODUS FLOW')
app.add_middleware(CORSMiddleware, allow_origins=[os.getenv('FRONTEND_ORIGIN','http://localhost:8000')], allow_credentials=True, allow_methods=['GET','POST'], allow_headers=['Content-Type','X-CSRF-Token'])
@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    errors = [{key: error[key] for key in ('type', 'loc', 'msg')} for error in exc.errors()]
    return JSONResponse({'detail': errors}, status_code=422)

ph=PasswordHasher(); attempts=defaultdict(deque)
def session():
    with Session() as db: yield db
@dataclass(frozen=True)
class Principal:
    id:int
    login:str
    role:str
    department_id:int|None
    permissions:frozenset[str] = frozenset()
def available_roles(db,user):
    result=[{'role':user.role,'department_id':user.department_id}]
    for grant in db.scalars(select(RoleGrant).where(RoleGrant.user_id==user.id)):
        item={'role':grant.role,'department_id':grant.department_id}
        if item not in result: result.append(item)
    return result
def assigned_role(db,user,role,department_id):
    return {'role':role,'department_id':department_id} in available_roles(db,user)
def current(request:Request, db=Depends(session)):
    try:
        payload=jwt.decode(request.cookies.get('session',''), SECRET, algorithms=['HS256'])
        if request.method not in ('GET','HEAD','OPTIONS') and not secrets.compare_digest(request.headers.get('X-CSRF-Token',''), payload['csrf']): raise ValueError()
        saved=db.get(AuthSession,hashlib.sha256(payload['jti'].encode()).hexdigest())
        if not saved or saved.user_id!=int(payload['sub']) or saved.expires_at<datetime.now(timezone.utc).replace(tzinfo=None): raise ValueError()
        user=db.get(User,int(payload['sub']))
        if not user or not user.active: raise ValueError()
        role=saved.selected_role or user.role; department_id=saved.selected_department_id if saved.selected_role else user.department_id
        if {'role':role,'department_id':department_id} not in available_roles(db,user): raise ValueError()
        principal = Principal(user.id, user.login, role, department_id,
                              frozenset(user_permissions(db, user.id)))
    except Exception: raise HTTPException(401,'Сессия недействительна или истекла')
    return principal
def roles(user,*allowed):
    if user.role not in allowed: raise HTTPException(403,'Недостаточно прав')
def visible(t,u):
    return u.role=='SUPER_ADMIN' or u.role in TICKET_REVIEW_ROLES or (u.role=='EMPLOYEE' and t.author_id==u.id) or (u.role=='DEPARTMENT_MANAGER' and t.department_id==u.department_id and t.department_id is not None) or (u.role=='EXECUTOR' and t.executor_id==u.id)
def ticket_or_404(db,tid,user):
    t=db.get(Ticket,tid)
    if not t or not visible(t,user): raise HTTPException(404,'Обращение не найдено')
    return t
def serialize(t):
    return {'id':t.id,'number':f'REQ-{t.id:06}','title':t.title,'description':t.description,'category':t.category,'solution':t.solution,'priority':t.priority,'preferred_department_id':t.preferred_department_id,'anonymous':t.token_hash is not None,'recommendation':t.recommendation,'reason':t.reason,'department_id':t.department_id,'executor_id':t.executor_id,'status':t.status,'result':t.result,'implemented':t.implemented,'due_at':t.due_at.isoformat() if t.due_at else None,'created_at':t.created_at.isoformat()}
def history(db,t,event): db.add(History(ticket_id=t.id,event=event))
def notify(db,t,message):
    if t.author_id is not None: db.add(Notification(user_id=t.author_id,ticket_id=t.id,message=message))
def detail_data(db,t):
    return serialize(t) | {'history':[{'event':h.event,'created_at':h.created_at.isoformat()} for h in db.scalars(select(History).where(History.ticket_id==t.id).order_by(History.id))], 'comments':[{'id':c.id,'author':c.author_label,'body':c.body,'created_at':c.created_at.isoformat()} for c in db.scalars(select(Comment).where(Comment.ticket_id==t.id).order_by(Comment.id))], 'attachments':[{'id':a.id,'name':a.name,'size':a.size} for a in db.scalars(select(Attachment).where(Attachment.ticket_id==t.id))], 'integration':[{'operation':e.operation,'result':e.result,'ok':e.ok} for e in db.scalars(select(IntegrationEvent).where(IntegrationEvent.ticket_id==t.id).order_by(IntegrationEvent.id))], 'external':[{'id':e.id,'external_id':e.external_id,'number':e.number,'status':e.status,'mode':e.mode} for e in db.scalars(select(ExternalEntity).where(ExternalEntity.ticket_id==t.id))]}
def anonymous_ticket(db,token):
    t=db.scalar(select(Ticket).where(Ticket.token_hash==hashlib.sha256(token.encode()).hexdigest()))
    if not t: raise HTTPException(404,'Обращение не найдено')
    return t
def routing_recommendation(db,title,description,category):
    text=(title+' '+description+' '+category).lower(); match=None
    for rule in db.scalars(select(RoutingRule).where(RoutingRule.active==True).order_by(RoutingRule.id)):
        dept=db.get(Department,rule.department_id)
        if rule.keyword.lower() in text and dept and dept.active: match=(dept.name,f'Совпадение по правилу «{rule.keyword}»'); break
    configured=db.scalar(select(RoutingRule.id).limit(1)) is not None
    department,reason=match or (('Руководство','Нет совпадения с активными правилами; требуется ручная проверка') if configured else recommend(title,description,category))
    if not db.scalar(select(Department).where(Department.name==department,Department.active==True)): return 'Не определён','Подходящий активный отдел не найден; требуется ручная проверка'
    return department,reason
def resume_after_info(t): return 'PENDING_ROUTING' if t.department_id is None else ('IN_PROGRESS' if t.executor_id else 'ASSIGNED')
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
class TicketEdit(BaseModel): title:str=Field(min_length=3,max_length=200); description:str=Field(min_length=5,max_length=5000); solution:str=Field(default='',max_length=2000)
class AnonymousEdit(TicketEdit,Token): pass
class AnonymousImage(Token): content_base64:str=Field(max_length=7_000_000)
class AnonymousDownload(Token): attachment_id:int
class DepartmentInput(BaseModel): name:str=Field(min_length=2,max_length=100); description:str=Field(default='',max_length=1000); active:bool=True
class UserInput(BaseModel): login:str=Field(min_length=3,max_length=100,pattern=r'^[A-Za-z0-9_.-]+$'); password:str=Field(min_length=12,max_length=200); role:str; department_id:int | None=None
class UserUpdate(BaseModel):
    login:str | None=Field(default=None,min_length=3,max_length=100,pattern=r'^[A-Za-z0-9_.-]+$')
    role:str
    department_id:int | None=None
    active:bool=True
class PasswordReset(BaseModel):
    password:str=Field(min_length=12,max_length=200)
class PasswordChange(PasswordReset):
    current_password:str=Field(min_length=1,max_length=200)
    confirmation:str=Field(max_length=200)
class PermissionInput(BaseModel):
    permissions:set[str]=Field(max_length=32)
class SystemSettingsInput(BaseModel):
    integration_mode:str=Field(pattern=r'^(MOCK|REAL)$')
class FileBody(BaseModel): name:str=Field(min_length=1,max_length=200); content_base64:str=Field(max_length=7_000_000)
class CategoryInput(BaseModel): name:str=Field(min_length=2,max_length=100); active:bool=True
class RuleInput(BaseModel): keyword:str=Field(min_length=2,max_length=100); department_id:int; active:bool=True
class RoleSelection(BaseModel): role:str; department_id:int|None=None
class GrantsInput(BaseModel): grants:list[RoleSelection]=Field(max_length=32)
class ImplementationInput(BaseModel): implemented:bool
@app.middleware('http')
async def headers(request, call_next):
    path=request.url.path
    if path.startswith('/api/') and os.getenv('RATE_LIMIT_ENABLED','1')!='0':
        group,limit=('credentials',10) if path in ('/api/login','/api/password') else (('anonymous',20) if path.startswith('/api/anonymous') else ('api',180))
        host=request.client.host if request.client else 'unknown'; key=hmac.new(SECRET.encode(),f'{group}:{host}'.encode(),hashlib.sha256).hexdigest(); period=int(time.time()//60)
        try:
            with Session.begin() as db:
                count=db.execute(text('INSERT INTO rate_limit_buckets (key,period,count) VALUES (:key,:period,1) ON CONFLICT (key) DO UPDATE SET count=CASE WHEN rate_limit_buckets.period=:period THEN rate_limit_buckets.count+1 ELSE 1 END, period=:period RETURNING count'),{'key':key,'period':period}).scalar_one()
                if secrets.randbelow(100)==0: db.execute(text('DELETE FROM rate_limit_buckets WHERE period < :cutoff'),{'cutoff':period-5})
            if count>limit: return JSONResponse({'detail':'Слишком много запросов'},status_code=429,headers={'Retry-After':'60','Cache-Control':'no-store'})
        except Exception: return JSONResponse({'detail':'Ограничитель запросов временно недоступен'},status_code=503,headers={'Cache-Control':'no-store'})
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'; response.headers['X-Frame-Options']='DENY'; response.headers['Referrer-Policy']='no-referrer'; response.headers['Cache-Control']='no-store' if path.startswith('/api/') else response.headers.get('Cache-Control','no-cache')
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
    verified_hash = user.password_hash
    user_id = user.id
    db.rollback()
    if db.bind.dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))
    user = db.get(User, user_id, with_for_update=True)
    if not user or not user.active or user.password_hash != verified_hash:
        raise HTTPException(401,'Неверный логин или пароль')
    csrf=secrets.token_urlsafe(32); jti=secrets.token_urlsafe(32); expires=datetime.now(timezone.utc)+timedelta(hours=8)
    db.add(AuthSession(id=hashlib.sha256(jti.encode()).hexdigest(),user_id=user.id,expires_at=expires.replace(tzinfo=None))); db.commit()
    token=jwt.encode({'sub':str(user.id),'csrf':csrf,'jti':jti,'exp':expires},SECRET,algorithm='HS256')
    response.set_cookie('session',token,httponly=True,samesite='strict',secure=os.getenv('COOKIE_SECURE')=='1',max_age=28800)
    return {'csrf':csrf,'login':user.login,'role':user.role,'department_id':user.department_id,'roles':available_roles(db,user),
            'permissions':user_permissions(db,user.id)}
@app.get('/api/me')
def me(request:Request,u=Depends(current),db=Depends(session)):
    payload=jwt.decode(request.cookies['session'],SECRET,algorithms=['HS256']); return {'login':u.login,'role':u.role,'department_id':u.department_id,'roles':available_roles(db,db.get(User,u.id)),'csrf':payload['csrf'], 'permissions':list(u.permissions)}
@app.post('/api/password')
def change_password(data:PasswordChange, request:Request, u=Depends(current), db=Depends(session)):
    if not secrets.compare_digest(data.password.encode(), data.confirmation.encode()):
        raise HTTPException(400, 'Подтверждение должно совпадать с новым паролем')
    if secrets.compare_digest(data.password.encode(), data.current_password.encode()):
        raise HTTPException(400, 'Новый пароль должен отличаться')
    if db.bind.dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))
    user = db.get(User, u.id, with_for_update=True)
    payload = jwt.decode(request.cookies['session'], SECRET, algorithms=['HS256'])
    session_id = hashlib.sha256(payload['jti'].encode()).hexdigest()
    if not user or not user.active or not db.get(AuthSession, session_id):
        raise HTTPException(401, 'Сессия недействительна')
    try:
        valid = ph.verify(user.password_hash, data.current_password)
    except Exception:
        valid = False
    if not valid:
        raise HTTPException(400, 'Текущий пароль неверен')
    user.password_hash = ph.hash(data.password)
    user.must_change_password = False
    revoke_sessions(db, user.id, keep=session_id)
    audit(db, u, 'Пароль изменён пользователем')
    db.commit()
    return {'ok': True}
@app.post('/api/session/role')
def switch_role(data:RoleSelection,request:Request,u=Depends(current),db=Depends(session)):
    user=db.get(User,u.id)
    if data.model_dump() not in available_roles(db,user): raise HTTPException(403,'Роль не назначена пользователю')
    if data.department_id is not None:
        dept=db.get(Department,data.department_id)
        if not dept or not dept.active: raise HTTPException(400,'Отдел недоступен')
    payload=jwt.decode(request.cookies['session'],SECRET,algorithms=['HS256']); saved=db.get(AuthSession,hashlib.sha256(payload['jti'].encode()).hexdigest())
    saved.selected_role=data.role; saved.selected_department_id=data.department_id; db.commit()
    return {'login':user.login,'role':data.role,'department_id':data.department_id,'roles':available_roles(db,user),'csrf':payload['csrf'], 'permissions':list(u.permissions)}
@app.post('/api/logout')
def logout(request:Request,response:Response,u=Depends(current),db=Depends(session)):
    payload=jwt.decode(request.cookies['session'],SECRET,algorithms=['HS256']); saved=db.get(AuthSession,hashlib.sha256(payload['jti'].encode()).hexdigest())
    if saved: db.delete(saved); db.commit()
    response.delete_cookie('session'); return {'ok':True}
@app.get('/api/departments')
def departments(u=Depends(current),db=Depends(session)):
    return [{'id':d.id,'name':d.name,'description':d.description,'active':d.active} for d in db.scalars(select(Department)) if d.active or permitted(u,'departments.manage') or u.role in TICKET_REVIEW_ROLES]
@app.get('/api/users')
def users(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER')
    result=[]
    for x in db.scalars(select(User)):
        memberships=available_roles(db,x)
        if u.role!='SUPER_ADMIN': memberships=[m for m in memberships if m['department_id']==u.department_id]
        if u.role=='SUPER_ADMIN' or memberships: result.append({'id':x.id,'login':x.login,'role':x.role if u.role=='SUPER_ADMIN' else memberships[0]['role'],'department_id':x.department_id if u.role=='SUPER_ADMIN' else u.department_id,'active':x.active,'roles':memberships})
    return result
@app.post('/api/tickets')
def create(data:NewTicket,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); raw=secrets.token_urlsafe(32) if data.anonymous else None
    if data.priority not in ('LOW','NORMAL','HIGH','URGENT'): raise HTTPException(400,'Недопустимый приоритет')
    if data.preferred_department_id is not None:
        preferred=db.get(Department,data.preferred_department_id)
        if not preferred or not preferred.active: raise HTTPException(400,'Отдел недоступен')
    department,reason=routing_recommendation(db,data.title,data.description,data.category)
    t=Ticket(title=data.title,description=data.description,category=data.category,solution=data.solution,priority=data.priority,preferred_department_id=data.preferred_department_id,author_id=None if raw else u.id,token_hash=hashlib.sha256(raw.encode()).hexdigest() if raw else None,recommendation=department,reason=reason,status='NEW')
    db.add(t); db.flush(); history(db,t,'Создано обращение'); notify(db,t,'Обращение создано')
    for admin in db.scalars(select(User).where(User.active==True)):
        if any(g['role']=='SUPER_ADMIN' for g in available_roles(db,admin)): db.add(Notification(user_id=admin.id,ticket_id=t.id,message='Новое обращение ожидает распределения'))
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
    if t.status=='NEEDS_INFO': t.status=resume_after_info(t); history(db,t,f'Статус: {t.status}')
    db.commit(); return detail_data(db,t)
def update_ticket_content(db,t,data):
    if t.status not in ('NEW','PENDING_ROUTING'): raise HTTPException(400,'Изменение доступно до распределения')
    t.title=data.title; t.description=data.description; t.solution=data.solution
    t.recommendation,t.reason=routing_recommendation(db,t.title,t.description,t.category)
    history(db,t,'Автор изменил обращение'); db.commit(); return detail_data(db,t)
@app.post('/api/anonymous/edit')
def anonymous_edit(data:AnonymousEdit,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); return update_ticket_content(db,anonymous_ticket(db,data.token),data)
@app.post('/api/anonymous/status')
def anonymous_status(data:AnonymousStatus,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); t=anonymous_ticket(db,data.token)
    if t.status!='RESOLVED' or data.status not in ('REOPENED','CLOSED'): raise HTTPException(400,'Недопустимый переход статуса')
    t.status=data.status; history(db,t,f'Статус: {t.status}'); db.commit(); return detail_data(db,t)
@app.post('/api/anonymous/attachments')
def anonymous_image(data:AnonymousImage,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); t=anonymous_ticket(db,data.token)
    if len(list(db.scalars(select(Attachment.id).where(Attachment.ticket_id==t.id))))>=10: raise HTTPException(400,'Не более 10 вложений')
    try:
        raw=base64.b64decode(data.content_base64,validate=True)
        if not raw or len(raw)>5*1024*1024: raise ValueError()
        with warnings.catch_warnings():
            warnings.simplefilter('error',Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as image:
                if image.format not in ('PNG','JPEG') or image.width*image.height>20_000_000: raise ValueError()
                image.load(); mode='RGBA' if 'A' in image.getbands() else 'RGB'
                clean=Image.new(mode,image.size); clean.paste(image.convert(mode))
                out=io.BytesIO(); clean.save(out,format='PNG',optimize=True); content=out.getvalue()
        if len(content)>5*1024*1024: raise ValueError()
    except (ValueError,binascii.Error,UnidentifiedImageError,OSError,Image.DecompressionBombError,Image.DecompressionBombWarning): raise HTTPException(400,'Нужен корректный PNG или JPEG до 5 МБ и 20 мегапикселей')
    folder=Path(os.getenv('UPLOAD_DIR','uploads')); folder.mkdir(parents=True,exist_ok=True); key=secrets.token_hex(24)+'.png'; path=folder/key
    try:
        with path.open('xb') as out: out.write(content)
        a=Attachment(ticket_id=t.id,name='Анонимное изображение.png',storage_key=key,size=len(content)); db.add(a); history(db,t,'Добавлено анонимное изображение'); db.commit()
    except Exception:
        path.unlink(missing_ok=True); raise
    return {'id':a.id,'name':a.name,'size':a.size}
@app.post('/api/anonymous/attachments/download')
def anonymous_download(data:AnonymousDownload,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); t=anonymous_ticket(db,data.token); a=db.get(Attachment,data.attachment_id)
    if not a or a.ticket_id!=t.id: raise HTTPException(404,'Вложение не найдено')
    path=Path(os.getenv('UPLOAD_DIR','uploads'))/a.storage_key
    if not path.is_file(): raise HTTPException(404,'Файл не найдено')
    return FileResponse(path,media_type='application/octet-stream',filename=a.name,headers={'X-Content-Type-Options':'nosniff'})
@app.get('/api/tickets/{tid}')
def detail(tid:int,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u)
    return detail_data(db,t) | {'attachments':[{'id':a.id,'name':a.name,'size':a.size} for a in db.scalars(select(Attachment).where(Attachment.ticket_id==t.id))]}
@app.post('/api/tickets/{tid}/edit')
def edit_ticket(tid:int,data:TicketEdit,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); t=ticket_or_404(db,tid,u)
    return update_ticket_content(db,t,data)
@app.post('/api/tickets/{tid}/attachments')
def attach(tid:int,data:FileBody,u=Depends(current),db=Depends(session)):
    if u.role in TICKET_REVIEW_ROLES: raise HTTPException(403,'Роль предназначена для просмотра обращений')
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
    if u.role in TICKET_REVIEW_ROLES: raise HTTPException(403,'Роль предназначена для просмотра обращений')
    t=ticket_or_404(db,tid,u)
    db.add(Comment(ticket_id=t.id,author_id=u.id,author_label=u.login,body=data.body)); history(db,t,'Добавлен комментарий'); notify(db,t,'Добавлен комментарий')
    if u.role=='EMPLOYEE' and t.status=='NEEDS_INFO': t.status=resume_after_info(t); history(db,t,f'Статус: {t.status}')
    db.commit(); return detail_data(db,t)
@app.post('/api/tickets/{tid}/route')
def route(tid:int,data:Route,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); t=ticket_or_404(db,tid,u); d=db.get(Department,data.department_id)
    if not d or not d.active: raise HTTPException(400,'Отдел недоступен')
    if t.status not in ('NEW','PENDING_ROUTING','ASSIGNED','IN_PROGRESS','NEEDS_INFO','REOPENED'): raise HTTPException(400,'Недопустимый переход')
    t.department_id=d.id; t.executor_id=None; t.due_at=None; t.status='ASSIGNED'; history(db,t,f'Назначен отдел: {d.name}'); db.add(TicketAssignment(ticket_id=t.id,department_id=d.id,actor_id=u.id,event='ROUTED')); db.add(AuditLog(actor_id=u.id,action=f'Назначен отдел для REQ-{t.id:06}')); notify(db,t,'Обращение распределено')
    for manager in db.scalars(select(User).where(User.active==True)):
        if assigned_role(db,manager,'DEPARTMENT_MANAGER',d.id): db.add(Notification(user_id=manager.id,ticket_id=t.id,message='Отделу назначено обращение'))
    db.commit(); return serialize(t)
@app.post('/api/tickets/{tid}/assign')
def assign(tid:int,data:Assign,u=Depends(current),db=Depends(session)):
    roles(u,'DEPARTMENT_MANAGER','SUPER_ADMIN'); t=ticket_or_404(db,tid,u); worker=db.get(User,data.executor_id)
    if t.status!='ASSIGNED' or not worker or not worker.active or not assigned_role(db,worker,'EXECUTOR',t.department_id): raise HTTPException(400,'Исполнитель или статус недоступен')
    if data.due_at is not None and data.due_at.tzinfo is None: raise HTTPException(400,'Укажите часовой пояс срока')
    t.executor_id=worker.id; t.due_at=data.due_at.astimezone(timezone.utc).replace(tzinfo=None) if data.due_at else None; t.status='IN_PROGRESS'; history(db,t,f'Назначен исполнитель: {worker.login}'); db.add(TicketAssignment(ticket_id=t.id,department_id=t.department_id,executor_id=worker.id,actor_id=u.id,event='ASSIGNED')); notify(db,t,'Назначен исполнитель'); db.add(Notification(user_id=worker.id,ticket_id=t.id,message='Вам назначено обращение')); db.commit(); return serialize(t)
@app.post('/api/tickets/{tid}/status')
def status(tid:int,data:Change,u=Depends(current),db=Depends(session)):
    if u.role in TICKET_REVIEW_ROLES: raise HTTPException(403,'Роль предназначена для просмотра обращений')
    t=ticket_or_404(db,tid,u)
    allowed={'EXECUTOR':{'IN_PROGRESS':{'NEEDS_INFO','RESOLVED'},'NEEDS_INFO':{'IN_PROGRESS'}},'DEPARTMENT_MANAGER':{'ASSIGNED':{'NEEDS_INFO','PENDING_ROUTING'},'IN_PROGRESS':{'NEEDS_INFO','RESOLVED','PENDING_ROUTING'},'NEEDS_INFO':{'IN_PROGRESS','PENDING_ROUTING'}},'EMPLOYEE':{'RESOLVED':{'REOPENED','CLOSED'}},'SUPER_ADMIN':{'NEW':{'REJECTED','NEEDS_INFO','PENDING_ROUTING'},'PENDING_ROUTING':{'REJECTED','NEEDS_INFO'},'ASSIGNED':{'PENDING_ROUTING','REJECTED','NEEDS_INFO'},'IN_PROGRESS':{'PENDING_ROUTING','REJECTED','NEEDS_INFO'},'NEEDS_INFO':{'PENDING_ROUTING','REJECTED'},'RESOLVED':{'CLOSED','REOPENED'},'REOPENED':{'PENDING_ROUTING','REJECTED'}}}
    if data.status not in allowed.get(u.role,{}).get(t.status,set()): raise HTTPException(400,'Недопустимый переход статуса')
    if data.status in ('RESOLVED','REJECTED','NEEDS_INFO','PENDING_ROUTING') and not data.result.strip(): raise HTTPException(400,'Укажите результат, вопрос или причину')
    if data.status=='PENDING_ROUTING':
        db.add(TicketAssignment(ticket_id=t.id,department_id=t.department_id,executor_id=t.executor_id,actor_id=u.id,event='RETURNED')); t.department_id=None; t.executor_id=None; t.due_at=None
    t.status=data.status
    if data.status in ('RESOLVED','REJECTED'): t.result=data.result
    history(db,t,f'Статус: {data.status}. {data.result}'); notify(db,t,f'Статус обращения: {data.status}'); db.commit(); return serialize(t)
@app.post('/api/tickets/{tid}/implementation')
def implementation(tid:int,data:ImplementationInput,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); t=ticket_or_404(db,tid,u)
    if t.status not in ('RESOLVED','CLOSED') or not t.solution.strip(): raise HTTPException(400,'Отметить можно решённое обращение с предложением')
    t.implemented=data.implemented; history(db,t,'Предложение отмечено реализованным' if data.implemented else 'Отметка о реализации снята'); db.add(AuditLog(actor_id=u.id,action=f'Изменена отметка предложения REQ-{tid:06}')); db.commit(); return serialize(t)
def integration_mode(db):
    setting = db.scalar(select(IntegrationSetting).where(IntegrationSetting.name == 'integration_mode'))
    return setting.value if setting else os.getenv('INTEGRATION_MODE', 'MOCK').upper()

def integrate(db,t,operation,fn):
    try: result=fn(); ok=True
    except Exception: result={'error':'Сервис 1С недоступен или вернул ошибку'}; ok=False
    db.add(IntegrationEvent(ticket_id=t.id,operation=operation,result=json.dumps(result,ensure_ascii=False),ok=ok))
    if not ok:
        for admin in db.scalars(select(User).where(User.active==True)):
            if any(g['role']=='SUPER_ADMIN' for g in available_roles(db,admin)): db.add(Notification(user_id=admin.id,ticket_id=t.id,message='Ошибка интеграции 1С'))
    db.commit()
    if not ok: raise HTTPException(502,result['error'])
    return result
@app.get('/api/tickets/{tid}/products')
def products(tid:int,q:str='',u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u)
    mode=integration_mode(db)
    return integrate(db,t,'Поиск товаров '+mode,lambda:integration_client(mode).get('/products',{'q':q}))
@app.post('/api/tickets/{tid}/orders')
def order(tid:int,data:Order,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u)
    scoped_key=hashlib.sha256(f'{t.id}:{data.key}'.encode()).hexdigest()
    mode=integration_mode(db)
    result=integrate(db,t,'Заявка '+mode,lambda:create_checked_order(integration_client(mode),{'item':data.item},scoped_key))
    external_id=str(result['id'])
    existing=db.scalar(select(ExternalEntity).where(ExternalEntity.ticket_id==t.id,ExternalEntity.external_id==external_id,ExternalEntity.mode==mode))
    if not existing: db.add(ExternalEntity(ticket_id=t.id,external_id=external_id,number=result['number'],status=result['status'],mode=mode)); db.commit()
    return result
@app.post('/api/tickets/{tid}/orders/{eid}/refresh')
def refresh_order(tid:int,eid:int,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u); entity=db.get(ExternalEntity,eid)
    if not entity or entity.ticket_id!=tid: raise HTTPException(404,'Заявка не найдена')
    if entity.mode!=integration_mode(db): raise HTTPException(400,'Режим интеграции изменился')
    result=integrate(db,t,'Проверка заявки '+entity.mode,lambda:get_checked_order(integration_client(entity.mode),entity.external_id)); entity.status=result['status']; db.commit(); return result
@app.get('/api/analytics')
def analytics(u=Depends(current),db=Depends(session)):
    require(u,'analytics.read'); ts=list(db.scalars(select(Ticket))); events=list(db.scalars(select(IntegrationEvent)))
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
    return {'total':len(ts),'new':sum(t.status=='NEW' for t in ts),'in_progress':sum(t.status=='IN_PROGRESS' for t in ts),'resolved':len(resolved),'implemented_suggestions':sum(t.implemented for t in ts),'overdue':sum(t.due_at is not None and t.due_at<now and t.status not in ('RESOLVED','CLOSED','REJECTED') for t in ts),'completion_rate':round(len(resolved)*100/len(ts),1) if ts else 0,'first_response_hours':avg(response_hours),'resolution_hours':avg(resolution_hours),'categories':categories,'departments':departments,'repeated_titles':{k:v for k,v in titles.items() if v>1},'integration_success':sum(e.ok for e in events),'integration_errors':sum(not e.ok for e in events)}
@app.get('/api/notifications')
def notifications(u=Depends(current),db=Depends(session)):
    return [{'id':n.id,'ticket_id':n.ticket_id,'message':n.message,'read':n.read,'created_at':n.created_at.isoformat()} for n in db.scalars(select(Notification).where(Notification.user_id==u.id).order_by(Notification.id.desc()).limit(100))]
@app.post('/api/notifications/{nid}/read')
def read_notification(nid:int,u=Depends(current),db=Depends(session)):
    n=db.get(Notification,nid)
    if not n or n.user_id!=u.id: raise HTTPException(404,'Уведомление не найдено')
    n.read=True; db.commit(); return {'ok':True}
@app.post('/api/departments')
def add_department(data:DepartmentInput,u=Depends(current),db=Depends(session)):
    require(u,'departments.manage')
    if db.scalar(select(Department).where(Department.name==data.name)): raise HTTPException(409,'Отдел уже существует')
    d=Department(**data.model_dump()); db.add(d); db.add(AuditLog(actor_id=u.id,action='Создан отдел '+data.name)); db.commit(); return {'id':d.id}
@app.post('/api/departments/{did}')
def edit_department(did:int,data:DepartmentInput,u=Depends(current),db=Depends(session)):
    require(u,'departments.manage'); d=db.get(Department,did)
    if not d: raise HTTPException(404,'Отдел не найден')
    other=db.scalar(select(Department).where(Department.name==data.name,Department.id!=did))
    if other: raise HTTPException(409,'Отдел уже существует')
    d.name=data.name; d.description=data.description; d.active=data.active; db.add(AuditLog(actor_id=u.id,action=f'Изменён отдел {did}')); db.commit(); return {'id':d.id}
@app.post('/api/users')
def add_user(data:UserInput,u=Depends(current),db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    return create_account(db, u, data, ph.hash(data.password))

@app.post('/api/users/{uid}')
def edit_user(uid:int,data:UserUpdate,u=Depends(current),db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    return update_account(db, u, uid, data)

@app.post('/api/users/{uid}/password')
def reset_password(uid:int, data:PasswordReset, u=Depends(current), db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    return reset_account_password(db, u, uid, ph.hash(data.password))

@app.get('/api/users/{uid}/permissions')
def get_permissions(uid:int, u=Depends(current), db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    account(db, uid)
    return {'catalog': PERMISSIONS, 'permissions': user_permissions(db, uid)}


@app.post('/api/users/{uid}/permissions')
def set_permissions(uid:int, data:PermissionInput, u=Depends(current), db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    return update_permissions(db, u, uid, data)

@app.get('/api/admin/audit')
def admin_audit(u=Depends(current), db=Depends(session)):
    require(u, 'audit.read')
    entries = db.execute(select(AuditLog, User.login).join(User, User.id == AuditLog.actor_id)
                         .order_by(AuditLog.id.desc()).limit(200))
    return [{'id': entry.id, 'actor': login, 'action': entry.action, 'created_at': entry.created_at.isoformat()}
            for entry, login in entries]


@app.get('/api/admin/data')
def data_status(u=Depends(current), db=Depends(session)):
    require(u, 'data.read')
    return database_status(db)


@app.get('/api/users/{uid}/grants')
def get_grants(uid:int,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); target=db.get(User,uid)
    if not target: raise HTTPException(404,'Пользователь не найден')
    return [{'role':g.role,'department_id':g.department_id} for g in db.scalars(select(RoleGrant).where(RoleGrant.user_id==uid))]
@app.post('/api/users/{uid}/grants')
def set_grants(uid:int,data:GrantsInput,u=Depends(current),db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    return update_grants(db, u, uid, data)

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
def integration_health(u=Depends(current),db=Depends(session)):
    if u.role not in ('DEPARTMENT_MANAGER','EXECUTOR'): require(u,'integration.read')
    mode=integration_mode(db)
    try: return {'mode':mode,'service':integration_client(mode).get('/health')}
    except Exception: raise HTTPException(502,'Сервис интеграции недоступен')
@app.get('/api/integration/events')
def integration_events(u=Depends(current),db=Depends(session)):
    require(u,'integration.read'); return [{'id':e.id,'ticket_id':e.ticket_id,'operation':e.operation,'ok':e.ok,'created_at':e.created_at.isoformat(),'result':e.result} for e in db.scalars(select(IntegrationEvent).order_by(IntegrationEvent.id.desc()).limit(200))]
@app.get('/api/integration/mock-history')
def mock_history(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN')
    if integration_mode(db)!='MOCK': raise HTTPException(400,'Доступно только в режиме MOCK')
    try: return integration_client('MOCK').get('/history')
    except Exception: raise HTTPException(502,'Симулятор недоступен')
@app.get('/api/categories')
def list_categories(u=Depends(current),db=Depends(session)):
    return [{'id':c.id,'name':c.name,'active':c.active} for c in db.scalars(select(Category)) if c.active or permitted(u,'categories.manage')]
@app.post('/api/categories')
def add_category(data:CategoryInput,u=Depends(current),db=Depends(session)):
    require(u,'categories.manage')
    if db.scalar(select(Category).where(Category.name==data.name)): raise HTTPException(409,'Категория уже существует')
    c=Category(**data.model_dump()); db.add(c); db.add(AuditLog(actor_id=u.id,action='Создана категория '+data.name)); db.commit(); return {'id':c.id}
@app.post('/api/categories/{cid}')
def edit_category(cid:int,data:CategoryInput,u=Depends(current),db=Depends(session)):
    require(u,'categories.manage'); c=db.get(Category,cid)
    if not c: raise HTTPException(404,'Категория не найдена')
    if db.scalar(select(Category).where(Category.name==data.name,Category.id!=cid)): raise HTTPException(409,'Категория уже существует')
    c.name=data.name; c.active=data.active; db.add(AuditLog(actor_id=u.id,action=f'Изменена категория {cid}')); db.commit(); return {'id':c.id}
@app.get('/api/routing-rules')
def list_rules(u=Depends(current),db=Depends(session)):
    require(u,'categories.manage'); return [{'id':r.id,'keyword':r.keyword,'department_id':r.department_id,'active':r.active} for r in db.scalars(select(RoutingRule))]
@app.post('/api/routing-rules')
def add_rule(data:RuleInput,u=Depends(current),db=Depends(session)):
    require(u,'categories.manage'); dept=db.get(Department,data.department_id)
    if not dept or not dept.active: raise HTTPException(400,'Отдел недоступен')
    if db.scalar(select(RoutingRule).where(RoutingRule.keyword==data.keyword.lower())): raise HTTPException(409,'Правило уже существует')
    r=RoutingRule(keyword=data.keyword.lower(),department_id=data.department_id,active=data.active); db.add(r); db.add(AuditLog(actor_id=u.id,action='Создано правило маршрутизации')); db.commit(); return {'id':r.id}
@app.post('/api/routing-rules/{rid}')
def edit_rule(rid:int,data:RuleInput,u=Depends(current),db=Depends(session)):
    require(u,'categories.manage'); r=db.get(RoutingRule,rid); dept=db.get(Department,data.department_id)
    if not r: raise HTTPException(404,'Правило не найдено')
    if not dept or (data.active and not dept.active): raise HTTPException(400,'Отдел недоступен')
    if db.scalar(select(RoutingRule).where(RoutingRule.keyword==data.keyword.lower(),RoutingRule.id!=rid)): raise HTTPException(409,'Правило уже существует')
    r.keyword=data.keyword.lower(); r.department_id=data.department_id; r.active=data.active; db.add(AuditLog(actor_id=u.id,action=f'Изменено правило {rid}')); db.commit(); return {'id':r.id}
@app.get('/api/admin/settings')
def system_settings(u=Depends(current), db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    return {'integration_mode': integration_mode(db)}

@app.post('/api/admin/settings')
def update_system_settings(data:SystemSettingsInput, u=Depends(current), db=Depends(session)):
    roles(u, 'SUPER_ADMIN')
    if data.integration_mode == 'REAL':
        try:
            integration_client('REAL')
        except (KeyError, ValueError):
            raise HTTPException(400, 'Настройте REAL_1C_URL, REAL_1C_USER и REAL_1C_PASSWORD на сервере')
    with account_transaction(db, u):
        setting = db.scalar(select(IntegrationSetting).where(IntegrationSetting.name == 'integration_mode'))
        if setting is None:
            setting = IntegrationSetting(name='integration_mode')
            db.add(setting)
        setting.value = data.integration_mode
        audit(db, u, f'Режим интеграции: {setting.value}')
    return {'integration_mode': data.integration_mode}
