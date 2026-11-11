import hashlib, os, secrets, time, json
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select
from argon2 import PasswordHasher
import jwt
from .models import Base, engine, Session, User, Department, Ticket, History, IntegrationEvent
from .routing import recommend
from .integration import Mock1CClient

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
        user=db.get(User,int(payload['sub']))
        if not user: raise ValueError()
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
    return {'id':t.id,'number':f'REQ-{t.id:06}','title':t.title,'description':t.description,'category':t.category,'solution':t.solution,'anonymous':t.token_hash is not None,'recommendation':t.recommendation,'reason':t.reason,'department_id':t.department_id,'executor_id':t.executor_id,'status':t.status,'result':t.result,'created_at':t.created_at.isoformat()}
def history(db,t,event): db.add(History(ticket_id=t.id,event=event))
class Login(BaseModel): login:str; password:str
class NewTicket(BaseModel):
    title:str=Field(min_length=3,max_length=200); description:str=Field(min_length=5,max_length=5000); category:str=Field(min_length=1,max_length=100); solution:str=Field(default='',max_length=2000); anonymous:bool=False
class Route(BaseModel): department_id:int
class Assign(BaseModel): executor_id:int
class Change(BaseModel): status:str; result:str=Field(default='',max_length=3000)
class Order(BaseModel): item:str=Field(min_length=1,max_length=200); key:str=Field(min_length=8,max_length=100)
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
    try: valid=user is not None and ph.verify(user.password_hash,data.password)
    except Exception: valid=False
    if not valid: raise HTTPException(401,'Неверный логин или пароль')
    csrf=secrets.token_urlsafe(32); token=jwt.encode({'sub':str(user.id),'csrf':csrf,'exp':datetime.now(timezone.utc)+timedelta(hours=8)},SECRET,algorithm='HS256')
    response.set_cookie('session',token,httponly=True,samesite='strict',secure=os.getenv('COOKIE_SECURE')=='1',max_age=28800)
    return {'csrf':csrf,'login':user.login,'role':user.role}
@app.get('/api/me')
def me(request:Request,u=Depends(current)):
    payload=jwt.decode(request.cookies['session'],SECRET,algorithms=['HS256']); return {'login':u.login,'role':u.role,'csrf':payload['csrf']}
@app.post('/api/logout')
def logout(response:Response,u=Depends(current)): response.delete_cookie('session'); return {'ok':True}
@app.get('/api/departments')
def departments(u=Depends(current),db=Depends(session)): return [{'id':d.id,'name':d.name} for d in db.scalars(select(Department).where(Department.active==True))]
@app.get('/api/users')
def users(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER')
    return [{'id':x.id,'login':x.login,'role':x.role,'department_id':x.department_id} for x in db.scalars(select(User)) if u.role=='SUPER_ADMIN' or x.department_id==u.department_id]
@app.post('/api/tickets')
def create(data:NewTicket,u=Depends(current),db=Depends(session)):
    roles(u,'EMPLOYEE'); raw=secrets.token_urlsafe(32) if data.anonymous else None
    department,reason=recommend(data.title,data.description,data.category)
    t=Ticket(title=data.title,description=data.description,category=data.category,solution=data.solution,author_id=None if raw else u.id,token_hash=hashlib.sha256(raw.encode()).hexdigest() if raw else None,recommendation=department,reason=reason,status='NEW')
    db.add(t); db.flush(); history(db,t,'Создано обращение'); db.commit()
    return {'ticket':serialize(t),'anonymous_token':raw}
@app.get('/api/tickets')
def tickets(u=Depends(current),db=Depends(session)):
    return [serialize(t) for t in db.scalars(select(Ticket).order_by(Ticket.id.desc())) if visible(t,u)]
@app.post('/api/anonymous')
def anonymous(data:dict, u=Depends(current),db=Depends(session)):
    token=data.get('token',''); digest=hashlib.sha256(token.encode()).hexdigest()
    t=db.scalar(select(Ticket).where(Ticket.token_hash==digest))
    if not t: raise HTTPException(404,'Обращение не найдено')
    return serialize(t)
@app.get('/api/tickets/{tid}')
def detail(tid:int,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u)
    return serialize(t) | {'history':[{'event':h.event,'created_at':h.created_at.isoformat()} for h in db.scalars(select(History).where(History.ticket_id==tid).order_by(History.id))], 'integration':[{'operation':e.operation,'result':e.result,'ok':e.ok} for e in db.scalars(select(IntegrationEvent).where(IntegrationEvent.ticket_id==tid).order_by(IntegrationEvent.id))]}
@app.post('/api/tickets/{tid}/route')
def route(tid:int,data:Route,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); t=ticket_or_404(db,tid,u); d=db.get(Department,data.department_id)
    if not d or not d.active: raise HTTPException(400,'Отдел недоступен')
    if t.status not in ('NEW','PENDING_ROUTING','ASSIGNED','REOPENED'): raise HTTPException(400,'Недопустимый переход')
    t.department_id=d.id; t.executor_id=None; t.status='ASSIGNED'; history(db,t,f'Назначен отдел: {d.name}'); db.commit(); return serialize(t)
@app.post('/api/tickets/{tid}/assign')
def assign(tid:int,data:Assign,u=Depends(current),db=Depends(session)):
    roles(u,'DEPARTMENT_MANAGER'); t=ticket_or_404(db,tid,u); worker=db.get(User,data.executor_id)
    if t.status!='ASSIGNED' or not worker or worker.role!='EXECUTOR' or worker.department_id!=u.department_id: raise HTTPException(400,'Исполнитель или статус недоступен')
    t.executor_id=worker.id; t.status='IN_PROGRESS'; history(db,t,f'Назначен исполнитель: {worker.login}'); db.commit(); return serialize(t)
@app.post('/api/tickets/{tid}/status')
def status(tid:int,data:Change,u=Depends(current),db=Depends(session)):
    t=ticket_or_404(db,tid,u)
    allowed={'EXECUTOR':{'IN_PROGRESS':{'NEEDS_INFO','RESOLVED'},'NEEDS_INFO':{'IN_PROGRESS'}},'DEPARTMENT_MANAGER':{'IN_PROGRESS':{'NEEDS_INFO','RESOLVED'},'NEEDS_INFO':{'IN_PROGRESS'}},'EMPLOYEE':{'RESOLVED':{'REOPENED','CLOSED'}},'SUPER_ADMIN':{'NEW':{'REJECTED','NEEDS_INFO'},'RESOLVED':{'CLOSED','REOPENED'},'REOPENED':{'PENDING_ROUTING'}}}
    if data.status not in allowed.get(u.role,{}).get(t.status,set()): raise HTTPException(400,'Недопустимый переход статуса')
    if data.status in ('RESOLVED','REJECTED') and not data.result.strip(): raise HTTPException(400,'Укажите результат или причину')
    t.status=data.status; t.result=data.result or t.result; history(db,t,f'Статус: {data.status}. {data.result}'); db.commit(); return serialize(t)
def integrate(db,t,operation,fn):
    try: result=fn(); ok=True
    except Exception: result={'error':'Сервис 1С недоступен или вернул ошибку'}; ok=False
    db.add(IntegrationEvent(ticket_id=t.id,operation=operation,result=json.dumps(result,ensure_ascii=False),ok=ok)); db.commit()
    if not ok: raise HTTPException(502,result['error'])
    return result
@app.get('/api/tickets/{tid}/products')
def products(tid:int,q:str='',u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u)
    return integrate(db,t,'Поиск товаров MOCK',lambda:Mock1CClient().get('/products',{'q':q}))
@app.post('/api/tickets/{tid}/orders')
def order(tid:int,data:Order,u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR'); t=ticket_or_404(db,tid,u)
    return integrate(db,t,'Заявка MOCK',lambda:Mock1CClient().create_order({'item':data.item},data.key))
@app.get('/api/analytics')
def analytics(u=Depends(current),db=Depends(session)):
    roles(u,'SUPER_ADMIN'); ts=list(db.scalars(select(Ticket))); events=list(db.scalars(select(IntegrationEvent)))
    return {'total':len(ts),'new':sum(t.status=='NEW' for t in ts),'in_progress':sum(t.status=='IN_PROGRESS' for t in ts),'resolved':sum(t.status in ('RESOLVED','CLOSED') for t in ts),'integration_success':sum(e.ok for e in events),'integration_errors':sum(not e.ok for e in events)}
app.mount('/',StaticFiles(directory='frontend',html=True),name='frontend')
