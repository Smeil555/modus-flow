import os, tempfile
from pathlib import Path
os.environ['SESSION_SECRET']='test-secret-with-at-least-thirty-two-characters'
os.environ['RATE_LIMIT_ENABLED']='0'
dbpath=Path(tempfile.mkdtemp())/'test.db'
os.environ['DATABASE_URL']='sqlite:///'+dbpath.as_posix()
from fastapi.testclient import TestClient
from argon2 import PasswordHasher
from backend.models import Base, engine, Session, User, Department, Ticket, History, Comment, Notification
from backend.operations_api import app, attempts
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
    import backend.operations_api as api
    from backend.models import IntegrationEvent
    attempts.clear(); admin=client('SUPER_ADMIN2')
    with Session.begin() as db:
        t=Ticket(title='Проверка контракта',description='Тестовые данные',category='IT',solution='',recommendation='IT',reason='test',status='NEW');db.add(t);db.flush();tid=t.id
    class BadClient:
        def create_order(self,data,key): return {'id':1}
    monkeypatch.setattr(api,'integration_client',lambda mode=None:BadClient())
    assert admin.post(f'/api/tickets/{tid}/orders',json={'item':'Сканер','key':'test-key-12345'}).status_code==502
    with Session() as db:
        event=db.scalar(select(IntegrationEvent).where(IntegrationEvent.ticket_id==tid));assert event is not None and not event.ok


def test_account_administration_and_password_lifecycle():
    attempts.clear()
    admin = client('SUPER_ADMIN2')
    department_id = admin.post('/api/departments', json={'name': 'Account test department'}).json()['id']
    temporary_password = 'temporary-test-password'
    response = admin.post('/api/users', json={
        'login': 'new-staff', 'role': 'EMPLOYEE', 'department_id': department_id, 'password': temporary_password,
    })
    assert response.status_code == 200, response.text
    uid = response.json()['id']
    assert admin.post('/api/users/2', json={'role': 'EMPLOYEE', 'active': False}).status_code == 400

    staff = TestClient(app)
    response = staff.post('/api/login', json={'login': 'new-staff', 'password': temporary_password})
    assert response.status_code == 200
    assert response.json()['department_id'] == department_id
    staff.headers['X-CSRF-Token'] = response.json()['csrf']
    assert staff.get('/api/tickets').status_code == 200
    other_session = TestClient(app)
    assert other_session.post('/api/login', json={'login': 'new-staff', 'password': temporary_password}).status_code == 200
    password_change = {
        'current_password': temporary_password, 'password': 'new-permanent-password',
        'confirmation': 'new-permanent-password',
    }
    assert staff.post('/api/password', json=password_change | {'confirmation': 'incorrect'}).status_code == 400
    assert staff.post('/api/password', json=password_change | {'current_password': 'incorrect'}).status_code == 400
    assert staff.post('/api/password', json=password_change).status_code == 200
    assert other_session.get('/api/me').status_code == 401
    assert other_session.post('/api/login', json={'login': 'new-staff', 'password': temporary_password}).status_code == 401
    assert other_session.post('/api/login', json={'login': 'new-staff', 'password': 'new-permanent-password'}).status_code == 200
    assert staff.get('/api/tickets').status_code == 200
    assert staff.post(f'/api/users/{uid}', json={'role': 'SUPER_ADMIN'}).status_code == 403
    assert staff.post(f'/api/users/{uid}/permissions', json={'permissions': ['audit.read']}).status_code == 403

    permissions = f'/api/users/{uid}/permissions'
    assert staff.get('/api/admin/data').status_code == 403
    assert admin.post(permissions, json={'permissions': ['data.read']}).status_code == 200
    assert staff.get('/api/admin/data').json()['engine'] == 'sqlite'
    assert admin.post(permissions, json={'permissions': []}).status_code == 200
    assert staff.get('/api/admin/data').status_code == 403

    assert admin.post(f'/api/users/{uid}', json={
        'login': 'renamed-staff', 'role': 'EXECUTOR', 'department_id': 1, 'active': False,
    }).status_code == 200
    assert staff.get('/api/me').status_code == 401
    assert admin.post(f'/api/users/{uid}/password', json={'password': 'replacement-temporary-password'}).status_code == 200
    assert admin.post(f'/api/users/{uid}', json={
        'role': 'EXECUTOR', 'department_id': 1, 'active': True,
    }).status_code == 200
    assert staff.post('/api/login', json={'login': 'renamed-staff', 'password': temporary_password}).status_code == 401
    assert staff.post('/api/login', json={
        'login': 'renamed-staff', 'password': 'replacement-temporary-password',
    }).status_code == 200

    audit = admin.get('/api/admin/audit')
    assert audit.status_code == 200
    assert all(value not in audit.text for value in (temporary_password, 'replacement-temporary-password'))
    assert any(entry['actor'] == 'SUPER_ADMIN2' and 'renamed-staff' in entry['action'] for entry in audit.json())


def test_initial_seed_and_account_persistence(tmp_path):
    import secrets
    import socket
    import sqlite3
    import subprocess
    import sys
    import time
    from contextlib import closing, contextmanager

    import httpx

    token = secrets.token_urlsafe(48)
    initial_password = 'initial-admin-test-password'
    environment = os.environ | {
        'DATABASE_URL': 'sqlite:///' + (tmp_path / 'operations.db').as_posix(),
        'INITIAL_ADMIN_PASSWORD': initial_password,
        'DATA_SERVICE_TOKEN': token,
        'DEMO_PASSWORD': '',
    }

    def run(*args):
        subprocess.run([sys.executable, *args], env=environment, check=True, capture_output=True, text=True)

    def free_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    @contextmanager
    def server(code, port, headers=None):
        url = f'http://127.0.0.1:{port}'
        with subprocess.Popen([sys.executable, '-c', code], env=environment) as process:
            try:
                with httpx.Client(base_url=url, headers=headers, trust_env=False, timeout=2) as probe:
                    for _ in range(100):
                        assert process.poll() is None
                        try:
                            if probe.get('/health').status_code == 200:
                                break
                        except httpx.TransportError:
                            pass
                        time.sleep(.1)
                    else:
                        raise AssertionError('service did not become ready')
                yield url
            finally:
                process.terminate()
                process.wait(timeout=10)

    @contextmanager
    def application():
        data_port, gateway_port = free_port(), free_port()
        while gateway_port == data_port:
            gateway_port = free_port()
        data_code = f'import uvicorn; uvicorn.run("backend.data_server:app", port={data_port}, proxy_headers=False)'
        gateway_code = (
            'import uvicorn; from backend import main; '
            f'main.DATA_URL = "http://127.0.0.1:{data_port}"; '
            f'uvicorn.run(main.app, port={gateway_port}, proxy_headers=False)'
        )
        with server(data_code, data_port, {'X-Modus-Service-Token': token}) as data:
            assert httpx.get(data + '/health', trust_env=False).status_code == 401
            with server(gateway_code, gateway_port) as gateway:
                with httpx.Client(base_url=gateway, trust_env=False) as admin:
                    response = admin.post('/api/login', json={'login': 'Smeil', 'password': initial_password})
                    assert response.status_code == 200
                    assert response.json()['role'] == 'SUPER_ADMIN'
                    admin.headers['X-CSRF-Token'] = response.json()['csrf']
                    yield admin, gateway

    run('-m', 'alembic', 'upgrade', 'head')
    run('-m', 'scripts.seed')
    with closing(sqlite3.connect(tmp_path / 'operations.db')) as db:
        assert {'ADMIN', 'ADMIN_ASSISTANT'} <= {row[0] for row in db.execute('SELECT name FROM roles')}
    with application() as (admin, gateway):
        for path in ('/users', '/analytics', '/admin/audit', '/admin/data', '/admin/settings',
                     '/routing-rules', '/departments', '/integration/events', '/tickets'):
            assert admin.get('/api' + path).status_code == 200, path
        response = admin.post('/api/users', json={
            'login': 'persistent-staff', 'password': 'staff-initial-password',
            'role': 'EMPLOYEE', 'department_id': 1,
        })
        assert response.status_code == 200
        uid = response.json()['id']
        assert admin.post(f'/api/users/{uid}/permissions', json={'permissions': ['data.read']}).status_code == 200
        with httpx.Client(base_url=gateway, trust_env=False) as staff:
            login = {'login': 'persistent-staff', 'password': 'staff-initial-password'}
            response = staff.post('/api/login', json=login)
            assert response.status_code == 200
            staff.headers['X-CSRF-Token'] = response.json()['csrf']
            assert staff.post(f'/api/users/{uid}', json={'role': 'SUPER_ADMIN'}).status_code == 403
            assert staff.get('/api/admin/data').status_code == 200
            departments = admin.get('/api/departments').json()[:2]
            review_tickets = []
            for department in departments:
                response = staff.post('/api/tickets', json={
                    'title': f"Review request for department {department['id']}",
                    'description': 'Cross-department review regression test',
                    'category': 'Оборудование',
                })
                assert response.status_code == 200
                ticket_id = response.json()['ticket']['id']
                assert admin.post(f'/api/tickets/{ticket_id}/route', json={
                    'department_id': department['id'],
                }).status_code == 200
                review_tickets.append((ticket_id, department['id']))
            assert staff.post('/api/password', json={
                'current_password': login['password'], 'password': 'staff-new-password',
                'confirmation': 'staff-new-password',
            }).status_code == 200
            assert staff.post('/api/login', json=login).status_code == 401

        for role in ('ADMIN', 'ADMIN_ASSISTANT'):
            reviewer_login = 'review-' + role.lower()
            response = admin.post('/api/users', json={
                'login': reviewer_login, 'password': 'review-test-password',
                'role': role if role == 'ADMIN' else 'EMPLOYEE',
                'department_id': departments[0]['id'],
            })
            assert response.status_code == 200
            reviewer_id = response.json()['id']
            if role == 'ADMIN_ASSISTANT':
                assert admin.post(f'/api/users/{reviewer_id}', json={
                    'role': role, 'department_id': departments[0]['id'],
                }).status_code == 200
            with httpx.Client(base_url=gateway, trust_env=False) as reviewer:
                response = reviewer.post('/api/login', json={'login': reviewer_login, 'password': 'review-test-password'})
                assert response.status_code == 200 and response.json()['role'] == role
                reviewer.headers['X-CSRF-Token'] = response.json()['csrf']
                assert {ticket['id'] for ticket in reviewer.get('/api/tickets').json()} >= {tid for tid, _ in review_tickets}
                for tid, department_id in review_tickets:
                    detail = reviewer.get(f'/api/tickets/{tid}').json()
                    assert detail['department_id'] == department_id
                    assert detail['status'] == 'ASSIGNED' and detail['history'] and detail['description']
                    assert reviewer.post(f'/api/tickets/{tid}/comments', json={'body': 'Forbidden'}).status_code == 403
                    assert reviewer.post(f'/api/tickets/{tid}/status', json={'status': 'REJECTED'}).status_code == 403
                    assert reviewer.post(f'/api/tickets/{tid}/route', json={'department_id': department_id}).status_code == 403
                assert reviewer.get('/api/users').status_code == 403

    environment['INITIAL_ADMIN_PASSWORD'] = 'different-seed-password'
    run('-m', 'scripts.seed')
    with application() as (admin, gateway):
        assert any(u['id'] == uid and u['department_id'] == 1 and u['role'] == 'EMPLOYEE'
                   for u in admin.get('/api/users').json())
        assert {u['role'] for u in admin.get('/api/users').json()} >= {'ADMIN', 'ADMIN_ASSISTANT'}
        assert admin.get('/api/admin/data').json()['database'] == 'operations.db'
        entries = admin.get('/api/admin/audit').json()
        assert any(e['actor'] == 'Smeil' and 'persistent-staff' in e['action'] for e in entries)
        assert all('staff-new-password' not in e['action'] for e in entries)
        with httpx.Client(base_url=gateway, trust_env=False) as staff:
            assert staff.post('/api/login', json={
                'login': 'persistent-staff', 'password': 'staff-new-password',
            }).status_code == 200
            assert staff.get('/api/admin/data').status_code == 200
