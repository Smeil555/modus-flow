import os, time, httpx

def safe_get(url,params=None,auth=None):
    with httpx.Client(timeout=5,auth=auth) as client:
        for attempt in range(2):
            try:
                response=client.get(url,params=params)
                if response.status_code>=500 and attempt==0:
                    time.sleep(.2); continue
                response.raise_for_status(); return response.json()
            except (httpx.TimeoutException,httpx.NetworkError):
                if attempt: raise
                time.sleep(.2)

class Mock1CClient:
    def __init__(self): self.url = os.getenv('MOCK_1C_URL', 'http://127.0.0.1:8001')
    def get(self, path, params=None):
        return safe_get(self.url+path,params)
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
        return safe_get(self.url+path,params,self.auth)
    def create_order(self,data,key):
        with httpx.Client(timeout=5,auth=self.auth) as client:
            r=client.post(self.url+'/orders',json=data,headers={'Idempotency-Key':key}); r.raise_for_status(); return r.json()

def integration_client():
    mode=os.getenv('INTEGRATION_MODE','MOCK').upper()
    if mode=='MOCK': return Mock1CClient()
    if mode=='REAL': return Real1CClient()
    raise ValueError('Invalid integration mode')

def create_checked_order(client,data,key):
    result=client.create_order(data,key)
    if not isinstance(result,dict) or not isinstance(result.get('id'),(str,int)) or not str(result['id']) or not isinstance(result.get('number'),str) or not result['number'] or not isinstance(result.get('status'),str) or not result['status']:
        raise ValueError('Invalid external order response')
    return result

def get_checked_order(client,external_id):
    from urllib.parse import quote
    result=client.get('/orders/'+quote(external_id,safe=''))
    if not isinstance(result,dict) or not isinstance(result.get('status'),str) or not result['status']: raise ValueError('Invalid external status response')
    return result
