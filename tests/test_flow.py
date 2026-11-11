import os, tempfile
from pathlib import Path
os.environ['SESSION_SECRET']='test-secret-with-at-least-thirty-two-characters'
os.environ['RATE_LIMIT_ENABLED']='0'
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
def test_multiple_roles_require_admin_grant_and_scoped_switch():
    attempts.clear(); admin=client('SUPER_ADMIN2'); employee=client('EMPLOYEE1')
    ticket=employee.post('/api/tickets',json={'title':'Сканер склада','description':'Сканер не работает','category':'Оборудование'}).json()['ticket']['id']
    assert employee.post('/api/session/role',json={'role':'SUPER_ADMIN','department_id':None}).status_code==403
    assert admin.post('/api/users/2/grants',json={'grants':[{'role':'EMPLOYEE','department_id':None}]}).status_code==403
    assert admin.post('/api/users/1/grants',json={'grants':[{'role':'DEPARTMENT_MANAGER','department_id':1}]}).status_code==200
    assert employee.get('/api/me').status_code==401
    employee=client('EMPLOYEE1')
    assert employee.post('/api/session/role',json={'role':'DEPARTMENT_MANAGER','department_id':1}).status_code==200
    assert employee.post('/api/tickets',json={'title':'Другой','description':'Длинное описание','category':'IT'}).status_code==403
    assert employee.get(f'/api/tickets/{ticket}').status_code==404
    assert admin.post(f'/api/tickets/{ticket}/route',json={'department_id':1}).status_code==200
    assert employee.get(f'/api/tickets/{ticket}').status_code==200
    assert employee.post('/api/session/role',json={'role':'EMPLOYEE','department_id':None}).status_code==200
    assert employee.get(f'/api/tickets/{ticket}').status_code==200
def test_deadline_notifications_are_idempotent_and_do_not_link_anonymous_author():
    from datetime import datetime, timedelta
    from backend.deadlines import generate_reminders
    from backend.models import DeadlineReminder
    attempts.clear(); employee=client('EMPLOYEE1'); admin=client('SUPER_ADMIN2'); manager=client('DEPARTMENT_MANAGER3')
    tid=employee.post('/api/tickets',json={'title':'Анонимный сканер','description':'Сканер не работает','category':'Оборудование','anonymous':True}).json()['ticket']['id']
    assert admin.post(f'/api/tickets/{tid}/route',json={'department_id':1}).status_code==200
    assert manager.post(f'/api/tickets/{tid}/assign',json={'executor_id':4,'due_at':'2030-01-01T14:00:00+05:00'}).status_code==200
    with Session() as db:
        assert db.get(Ticket,tid).due_at==datetime(2030,1,1,9,0)
        start=datetime(2030,1,1,8,0); count=generate_reminders(db,start); assert count>=3
        assert generate_reminders(db,start)==0
        assert not db.scalar(select(DeadlineReminder).where(DeadlineReminder.ticket_id==tid,DeadlineReminder.user_id==1)) is None  # manager role, not author identity
        assert db.get(Ticket,tid).author_id is None
        assert generate_reminders(db,start+timedelta(hours=2))>=3
def test_anonymous_image_strips_metadata_and_requires_token(tmp_path,monkeypatch):
    import base64,io
    from PIL import Image,PngImagePlugin
    from backend.models import Attachment
    attempts.clear(); monkeypatch.setenv('UPLOAD_DIR',str(tmp_path)); employee=client('EMPLOYEE1'); admin=client('SUPER_ADMIN2')
    created=employee.post('/api/tickets',json={'title':'Изображение проблемы','description':'Нужна помощь с устройством','category':'Оборудование','anonymous':True}).json(); token=created['anonymous_token']; tid=created['ticket']['id']
    metadata=PngImagePlugin.PngInfo(); metadata.add_text('Author','Private Author Name')
    image=Image.new('RGB',(3,3),'red'); source=io.BytesIO(); image.save(source,format='PNG',pnginfo=metadata)
    payload={'token':token,'content_base64':base64.b64encode(source.getvalue()).decode()}
    r=employee.post('/api/anonymous/attachments',json=payload); assert r.status_code==200; aid=r.json()['id']
    assert r.json()['name']=='Анонимное изображение.png'
    assert employee.post('/api/anonymous/attachments/download',json={'token':'z'*40,'attachment_id':aid}).status_code==404
    saved=employee.post('/api/anonymous/attachments/download',json={'token':token,'attachment_id':aid}); assert saved.status_code==200
    assert b'Private Author Name' not in saved.content
    with Image.open(io.BytesIO(saved.content)) as result: assert 'Author' not in result.info
    with Session() as db:
        assert db.get(Ticket,tid).author_id is None
        assert db.get(Attachment,aid).name=='Анонимное изображение.png'
    assert admin.get(f'/api/tickets/{tid}/attachments/{aid}').status_code==200
def test_edit_and_return_for_routing():
    attempts.clear(); employee=client('EMPLOYEE1'); admin=client('SUPER_ADMIN2'); manager=client('DEPARTMENT_MANAGER3')
    created=employee.post('/api/tickets',json={'title':'Проблема склада','description':'Описание проблемы склада','category':'Оборудование','anonymous':True}).json(); tid=created['ticket']['id']; token=created['anonymous_token']
    data={'token':token,'title':'Обновлённый сканер','description':'Сканер перестал читать штрихкоды','solution':'Заменить'}
    assert employee.post('/api/anonymous/edit',json=data).json()['title']==data['title']
    assert admin.post(f'/api/tickets/{tid}/route',json={'department_id':1}).status_code==200
    assert employee.post('/api/anonymous/edit',json=data).status_code==400
    assert manager.post(f'/api/tickets/{tid}/status',json={'status':'NEEDS_INFO','result':'Уточните модель'}).status_code==200
    assert employee.post('/api/anonymous/comment',json={'token':token,'body':'Модель указана'}).json()['status']=='ASSIGNED'
    assert manager.post(f'/api/tickets/{tid}/status',json={'status':'PENDING_ROUTING','result':'Нужен другой отдел'}).status_code==200
    assert manager.get(f'/api/tickets/{tid}').status_code==404
def test_shared_rate_limit_without_storing_ip_or_token(monkeypatch):
    from backend.models import RateLimitBucket
    monkeypatch.setenv('RATE_LIMIT_ENABLED','1')
    with Session.begin() as db:
        for row in db.scalars(select(RateLimitBucket)): db.delete(row)
    a=TestClient(app); b=TestClient(app)
    results=[(a if i%2 else b).post('/api/anonymous',json={'token':'a'*40}).status_code for i in range(21)]
    assert results[:20]==[401]*20 and results[20]==429
    with Session() as db:
        records=list(db.scalars(select(RateLimitBucket))); assert len(records)==1
        assert 'testclient' not in records[0].key and 'a'*40 not in records[0].key
def test_implemented_suggestion_and_assignment_history():
    from backend.models import TicketAssignment
    attempts.clear(); employee=client('EMPLOYEE1'); admin=client('SUPER_ADMIN2'); manager=client('DEPARTMENT_MANAGER3'); executor=client('EXECUTOR4')
    tid=employee.post('/api/tickets',json={'title':'Заменить сканер','description':'Устройство больше не работает','category':'Оборудование','solution':'Заменить устройство'}).json()['ticket']['id']
    assert admin.post(f'/api/tickets/{tid}/implementation',json={'implemented':True}).status_code==400
    assert admin.post(f'/api/tickets/{tid}/route',json={'department_id':1}).status_code==200
    assert manager.post(f'/api/tickets/{tid}/assign',json={'executor_id':4}).status_code==200
    assert executor.post(f'/api/tickets/{tid}/status',json={'status':'RESOLVED','result':'Устройство заменено'}).status_code==200
    assert employee.post(f'/api/tickets/{tid}/implementation',json={'implemented':True}).status_code==403
    assert admin.post(f'/api/tickets/{tid}/implementation',json={'implemented':True}).status_code==200
    assert admin.get('/api/analytics').json()['implemented_suggestions']>=1
    with Session() as db:
        events=list(db.scalars(select(TicketAssignment).where(TicketAssignment.ticket_id==tid).order_by(TicketAssignment.id)))
        assert [e.event for e in events]==['ROUTED','ASSIGNED']
def test_full_integration_records_idempotent_order_and_refresh(tmp_path,monkeypatch):
    import os,socket,subprocess,sys,time,httpx
    from backend.models import IntegrationEvent,ExternalEntity
    attempts.clear(); admin=client('SUPER_ADMIN2'); employee=client('EMPLOYEE1'); manager=client('DEPARTMENT_MANAGER3'); executor=client('EXECUTOR4')
    tid=employee.post('/api/tickets',json={'title':'Заявка на сканер','description':'Не работает складской сканер','category':'Оборудование'}).json()['ticket']['id']
    assert admin.post(f'/api/tickets/{tid}/route',json={'department_id':1}).status_code==200
    assert manager.post(f'/api/tickets/{tid}/assign',json={'executor_id':4}).status_code==200
    with socket.socket() as sock: sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    env=os.environ.copy();env['MOCK_DB']=str(tmp_path/'mock.db');url=f'http://127.0.0.1:{port}';monkeypatch.setenv('MOCK_1C_URL',url)
    process=subprocess.Popen([sys.executable,'-m','uvicorn','mock_1c.main:app','--host','127.0.0.1','--port',str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                if httpx.get(url+'/health',timeout=.2).status_code==200: break
            except httpx.HTTPError: time.sleep(.1)
        assert executor.get(f'/api/tickets/{tid}/products',params={'q':'Zebra'}).json()[0]['stock']==0
        body={'item':'Сканер','key':'stable-key-1234'}
        first=executor.post(f'/api/tickets/{tid}/orders',json=body);second=executor.post(f'/api/tickets/{tid}/orders',json=body)
        assert first.status_code==200 and first.json()['id']==second.json()['id']
        with Session() as db:
            links=list(db.scalars(select(ExternalEntity).where(ExternalEntity.ticket_id==tid))); assert len(links)==1; eid=links[0].id
        assert httpx.patch(url+'/orders/'+str(first.json()['id']),json={'status':'APPROVED'}).status_code==200
        assert executor.post(f'/api/tickets/{tid}/orders/{eid}/refresh',json={}).json()['status']=='APPROVED'
        with Session() as db:
            assert db.get(ExternalEntity,eid).status=='APPROVED'
            assert len(list(db.scalars(select(IntegrationEvent).where(IntegrationEvent.ticket_id==tid))))==4
    finally:
        process.terminate();process.wait(timeout=5)
    assert executor.get(f'/api/tickets/{tid}/products').status_code==502
    with Session() as db: assert any(not e.ok for e in db.scalars(select(IntegrationEvent).where(IntegrationEvent.ticket_id==tid)))
def test_sqlite_backup_does_not_overwrite(tmp_path):
    import sqlite3,pytest
    from scripts.backup import backup_database
    target=tmp_path/'backup.db'; backup_database(dbpath,target)
    with sqlite3.connect(target) as copy: assert copy.execute('select count(*) from tickets').fetchone()[0]>0
    with pytest.raises(ValueError): backup_database(dbpath,target)
    with sqlite3.connect(target) as copy: assert copy.execute('pragma integrity_check').fetchone()[0]=='ok'
def test_invalid_external_order_is_recorded_as_failure(monkeypatch):
    import backend.main as api
    from backend.models import IntegrationEvent
    attempts.clear(); admin=client('SUPER_ADMIN2')
    with Session.begin() as db:
        t=Ticket(title='Проверка контракта',description='Тестовые данные',category='IT',solution='',recommendation='IT',reason='test',status='NEW');db.add(t);db.flush();tid=t.id
    class BadClient:
        def create_order(self,data,key): return {'id':1}
    monkeypatch.setattr(api,'integration_client',lambda:BadClient())
    assert admin.post(f'/api/tickets/{tid}/orders',json={'item':'Сканер','key':'test-key-12345'}).status_code==502
    with Session() as db:
        event=db.scalar(select(IntegrationEvent).where(IntegrationEvent.ticket_id==tid));assert event is not None and not event.ok
