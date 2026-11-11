import os, httpx

class Mock1CClient:
    def __init__(self): self.url = os.getenv('MOCK_1C_URL', 'http://127.0.0.1:8001')
    def get(self, path, params=None):
        with httpx.Client(timeout=4) as client:
            response=client.get(self.url+path, params=params); response.raise_for_status(); return response.json()
    def create_order(self, data, key):
        with httpx.Client(timeout=4) as client:
            response=client.post(self.url+'/orders', json=data, headers={'Idempotency-Key':key}); response.raise_for_status(); return response.json()
