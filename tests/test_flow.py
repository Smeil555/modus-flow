import os, tempfile
from pathlib import Path
os.environ['SESSION_SECRET']='test-secret-with-at-least-thirty-two-characters'
dbpath=Path(tempfile.mkdtemp())/'test.db'
os.environ['DATABASE_URL']='sqlite:///'+dbpath.as_posix()
from fastapi.testclient import TestClient
from argon2 import PasswordHasher
from backend.models import Base, engine, Session, User, Department, Ticket, History
from backend.main import app
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
