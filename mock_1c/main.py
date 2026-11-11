from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import sqlite3, os

app=FastAPI(title='Mock 1C UT — демонстрация')
DB=os.getenv('MOCK_DB','mock1c.db')
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, idem TEXT UNIQUE, item TEXT, status TEXT, created_at TEXT)'); return c
class Order(BaseModel): item: str=Field(min_length=1,max_length=200)
@app.get('/health')
def health(): return {'mode':'MOCK','status':'ok'}
@app.get('/products')
def products(q: str=''):
    items=[{'code':'000001','name':'Сканер штрихкодов Zebra DS2208','sku':'DS2208','stock':0,'unit':'шт.','warehouse':'Основной склад'}, {'code':'000002','name':'Сканер штрихкодов Honeywell','sku':'HW-01','stock':2,'unit':'шт.','warehouse':'Основной склад'}]
    return [x for x in items if q.lower() in x['name'].lower() or q.lower() in x['sku'].lower()]
@app.post('/orders')
def order(body:Order, idempotency_key:str=Header(min_length=8,max_length=100)):
    with db() as c:
        c.execute('INSERT OR IGNORE INTO orders(idem,item,status,created_at) VALUES (?,?,?,?)',(idempotency_key,body.item,'CREATED',datetime.now(timezone.utc).isoformat()))
        row=c.execute('SELECT id,item,status,created_at FROM orders WHERE idem=?',(idempotency_key,)).fetchone()
        return dict(row) | {'number':f'MOCK-{row["id"]:06}'}
@app.get('/orders/{order_id}')
def get_order(order_id:int):
    with db() as c: row=c.execute('SELECT id,item,status,created_at FROM orders WHERE id=?',(order_id,)).fetchone()
    if not row: raise HTTPException(404,'Заявка не найдена')
    return dict(row) | {'number':f'MOCK-{row["id"]:06}'}
