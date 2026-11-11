import os, httpx

class Mock1CClient:
    def __init__(self): self.url = os.getenv('MOCK_1C_URL', 'http://127.0.0.1:8001')
    def get(self, path, params=None):
        with httpx.Client(timeout=4) as client:
            response=client.get(self.url+path, params=params); response.raise_for_status(); return response.json()
    def create_order(self, data, key):
        with httpx.Client(timeout=4) as client:
            response=client.post(self.url+'/orders', json=data, headers={'Idempotency-Key':key}); response.raise_for_status(); return response.json()

class Real1CClient:
    """Adapter for a separately agreed HTTP service, not a generic 1C mapping."""
    def __init__(self):
        self.url=os.environ['REAL_1C_URL'].rstrip('/')
        if not self.url.startswith('https://'): raise ValueError('REAL_1C_URL must use HTTPS')
        self.auth=(os.environ['REAL_1C_USER'],os.environ['REAL_1C_PASSWORD'])
    def get(self,path,params=None):
        with httpx.Client(timeout=5,auth=self.auth) as client:
            r=client.get(self.url+path,params=params); r.raise_for_status(); return r.json()
    def create_order(self,data,key):
        with httpx.Client(timeout=5,auth=self.auth) as client:
            r=client.post(self.url+'/orders',json=data,headers={'Idempotency-Key':key}); r.raise_for_status(); return r.json()

def integration_client():
    mode=os.getenv('INTEGRATION_MODE','MOCK').upper()
    if mode=='MOCK': return Mock1CClient()
    if mode=='REAL': return Real1CClient()
    raise ValueError('Invalid integration mode')
