import os, tempfile
from pathlib import Path
os.environ['SESSION_SECRET']='test-secret-with-at-least-thirty-two-characters'
dbpath=Path(tempfile.mkdtemp())/'test.db'
os.environ['DATABASE_URL']='sqlite:///'+dbpath.as_posix()
from fastapi.testclient import TestClient
from argon2 import PasswordHasher
from backend.models import Base, engine, Session, User, Department, Ticket, History, Comment, Notification
from backend.main import app, attempts
from sqlalchemy import select

Base.metadata.create_all(engine)
with Session.begin() as db:
    db.add_all([Department(id=1,name='Технический отдел'),Department(id=2,name='IT-отдел')]); db.flush()
    for i,role,dep in [(1,'EMPLOYEE',None),(2,'SUPER_ADMIN',None),(3,'DEPARTMENT_MANAGER',1),(4,'EXECUTOR',1),(5,'EXECUTOR',2)]:
        db.add(User(id=i,login=role+str(i),password_hash=PasswordHasher().hash('test-password-123'),role=role,department_id=dep))
def client(login):
    c=TestClient(app); r=c.post('/api/login',json={'login':login,'password':'test-password-123'}); assert r.status_code==200; c.headers['X-CSRF-Token']=r.json()['csrf']; return c
def test_anonymous_routing_and_isolation():
    employee=client('EMPLOYEE1'); admin=client('SUPER_ADMIN2'); manager=client('DEPARTMENT_MANAGER3'); executor=client('EXECUTOR4'); outsider=client('EXECUTOR5')
    r=employee.post('/api/tickets',json={'title':'Не работает сканер','description':'Сканер сломался на складе','category':'Оборудование','anonymous':True}); assert r.status_code==200
    result=r.json(); tid=result['ticket']['id']; token=result['anonymous_token']; assert result['ticket']['recommendation']=='Технический отдел'
    with Session() as db:
        ticket=db.get(Ticket,tid); assert ticket.author_id is None; assert token != ticket.token_hash; assert all('EMPLOYEE1' not in h.event for h in db.scalars(select(History)))
    assert employee.get(f'/api/tickets/{tid}').status_code==404
    assert employee.post('/api/anonymous',json={'token':token}).json()['id']==tid
    assert manager.get(f'/api/tickets/{tid}').status_code==404
    assert admin.post(f'/api/tickets/{tid}/route',json={'department_id':1}).status_code==200
    assert manager.post(f'/api/tickets/{tid}/assign',json={'executor_id':4}).status_code==200
    assert outsider.get(f'/api/tickets/{tid}').status_code==404
    assert executor.post(f'/api/tickets/{tid}/status',json={'status':'CLOSED'}).status_code==400
    assert executor.post(f'/api/tickets/{tid}/status',json={'status':'RESOLVED','result':'Заменён'}).status_code==200
    assert 'author_id' not in admin.get(f'/api/tickets/{tid}').json()
def test_csrf():
    c=client('EMPLOYEE1'); c.headers['X-CSRF-Token']='bad'; assert c.post('/api/tickets',json={'title':'тест','description':'описание','category':'тест'}).status_code==401
def test_anonymous_followup_and_notifications():
    attempts.clear(); employee=client('EMPLOYEE1'); admin=client('SUPER_ADMIN2')
    created=employee.post('/api/tickets',json={'title':'Проблема склада','description':'Неисправность оборудования','category':'Склад','anonymous':True}).json(); tid=created['ticket']['id']; token=created['anonymous_token']
    assert admin.post(f'/api/tickets/{tid}/status',json={'status':'NEEDS_INFO','result':'Уточните'}).status_code==200
    assert employee.post('/api/anonymous/comment',json={'token':token,'body':'Ответ без имени'}).json()['status']=='PENDING_ROUTING'
    with Session() as db:
        comment=db.scalar(select(Comment).where(Comment.ticket_id==tid)); assert comment.author_id is None
        assert not list(db.scalars(select(Notification).where(Notification.ticket_id==tid,Notification.user_id==1)))
    assert employee.post('/api/anonymous',json={'token':'x'*40}).status_code==404
def test_attachment_access_and_path_safety(tmp_path,monkeypatch):
    import base64
    attempts.clear(); monkeypatch.setenv('UPLOAD_DIR',str(tmp_path)); employee=client('EMPLOYEE1'); outsider=client('EXECUTOR5')
    tid=employee.post('/api/tickets',json={'title':'Новая проблема','description':'Описание проблемы','category':'IT'}).json()['ticket']['id']
    r=employee.post(f'/api/tickets/{tid}/attachments',json={'name':'../../notes.txt','content_base64':base64.b64encode(b'hello').decode()}); assert r.status_code==200; assert r.json()['name']=='notes.txt'
    aid=r.json()['id']; assert employee.get(f'/api/tickets/{tid}/attachments/{aid}').content==b'hello'
    assert outsider.get(f'/api/tickets/{tid}/attachments/{aid}').status_code==404
    assert employee.post(f'/api/tickets/{tid}/attachments',json={'name':'bad.pdf','content_base64':base64.b64encode(b'not a PDF').decode()}).status_code==400
def test_department_admin_and_user_privilege():
    attempts.clear(); employee=client('EMPLOYEE1'); admin=client('SUPER_ADMIN2')
    body={'name':'Новый отдел','description':'Тест','active':True}
    assert employee.post('/api/departments',json=body).status_code==403
    r=admin.post('/api/departments',json=body); assert r.status_code==200
    assert admin.post('/api/departments/'+str(r.json()['id']),json={**body,'active':False}).status_code==200
    assert employee.post('/api/users',json={'login':'intruder','password':'password-long-enough','role':'SUPER_ADMIN'}).status_code==403
    assert admin.post('/api/users/2',json={'role':'EMPLOYEE','active':True}).status_code==400
    assert admin.post('/api/users/1',json={'role':'EMPLOYEE','active':False}).status_code==200
    assert employee.get('/api/me').status_code==401
    assert admin.post('/api/users/1',json={'role':'EMPLOYEE','active':True}).status_code==200
def test_logout_revokes_cookie():
    attempts.clear(); c=client('EMPLOYEE1'); token=c.cookies.get('session'); assert c.post('/api/logout').status_code==200
    c.cookies.set('session',token); assert c.get('/api/me').status_code==401
def test_configured_routing_and_inactive_department():
    attempts.clear(); admin=client('SUPER_ADMIN2'); employee=client('EMPLOYEE1')
    assert employee.post('/api/routing-rules',json={'keyword':'принтер','department_id':2}).status_code==403
    rule=admin.post('/api/routing-rules',json={'keyword':'принтер','department_id':2}); assert rule.status_code==200
    body={'title':'Принтер сломан','description':'Принтер не печатает документы','category':'IT','preferred_department_id':2,'priority':'HIGH'}
    first=employee.post('/api/tickets',json=body).json()['ticket']; assert first['recommendation']=='IT-отдел'; assert first['priority']=='HIGH'
    filtered=employee.get('/api/tickets',params={'priority':'HIGH','category':'IT'}).json()
    assert any(t['id']==first['id'] for t in filtered) and all(t['priority']=='HIGH' and t['category']=='IT' for t in filtered)
    assert admin.post('/api/routing-rules/'+str(rule.json()['id']),json={'keyword':'принтер','department_id':2,'active':False}).status_code==200
    assert employee.post('/api/tickets',json=body).json()['ticket']['recommendation']!='IT-отдел'
    assert admin.post('/api/departments/2',json={'name':'IT-отдел','description':'','active':False}).status_code==200
    assert employee.post('/api/tickets',json=body).status_code==400
    body['preferred_department_id']=None
    second=employee.post('/api/tickets',json=body).json()['ticket']; assert second['recommendation']!='IT-отдел'
