import os, socket, subprocess, sys, time
import httpx
from backend.integration import Mock1CClient

def test_separate_mock_service(tmp_path, monkeypatch):
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    env=os.environ.copy(); env['MOCK_DB']=str(tmp_path/'mock.db')
    process=subprocess.Popen([sys.executable,'-m','uvicorn','mock_1c.main:app','--host','127.0.0.1','--port',str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    url=f'http://127.0.0.1:{port}'; monkeypatch.setenv('MOCK_1C_URL',url)
    try:
        for _ in range(60):
            try:
                if httpx.get(url+'/health',timeout=.2).status_code==200: break
            except httpx.HTTPError: time.sleep(.1)
        client=Mock1CClient(); products=client.get('/products',{'q':'Zebra'}); assert products[0]['stock']==0
        first=client.create_order({'item':'scanner'},'test-idempotency-key'); second=client.create_order({'item':'scanner'},'test-idempotency-key')
        assert first['id']==second['id']; assert client.get('/orders/'+str(first['id']))['status']=='CREATED'
    finally:
        process.terminate(); process.wait(timeout=5)
