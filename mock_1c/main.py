from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import sqlite3, os

app=FastAPI(title='Mock 1C UT — демонстрация')
DB=os.getenv('MOCK_DB','mock1c.db')
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, idem TEXT UNIQUE, item TEXT, status TEXT, created_at TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS request_log (id INTEGER PRIMARY KEY, operation TEXT, created_at TEXT)'); return c
def log(operation):
    with db() as c: c.execute('INSERT INTO request_log(operation,created_at) VALUES (?,?)',(operation,datetime.now(timezone.utc).isoformat()))
class Order(BaseModel): item: str=Field(min_length=1,max_length=200)
class OrderStatus(BaseModel): status:str
@app.get('/health')
def health(): return {'mode':'MOCK','status':'ok'}
@app.get('/products')
def products(q: str=''):
    log('products')
    items=[{'code':'000001','name':'Сканер штрихкодов Zebra DS2208','sku':'DS2208','stock':0,'unit':'шт.','warehouse':'Основной склад'}, {'code':'000002','name':'Сканер штрихкодов Honeywell','sku':'HW-01','stock':2,'unit':'шт.','warehouse':'Основной склад'}]
    return [x for x in items if q.lower() in x['name'].lower() or q.lower() in x['sku'].lower()]
@app.post('/orders')
def order(body:Order, idempotency_key:str=Header(min_length=8,max_length=100)):
    log('create_order')
    with db() as c:
        c.execute('INSERT OR IGNORE INTO orders(idem,item,status,created_at) VALUES (?,?,?,?)',(idempotency_key,body.item,'CREATED',datetime.now(timezone.utc).isoformat()))
        row=c.execute('SELECT id,item,status,created_at FROM orders WHERE idem=?',(idempotency_key,)).fetchone()
        if row['item']!=body.item: raise HTTPException(409,'Ключ идемпотентности уже использован для другой заявки')
        return dict(row) | {'number':f'MOCK-{row["id"]:06}'}
@app.get('/orders/{order_id}')
def get_order(order_id:int):
    log('get_order')
    with db() as c: row=c.execute('SELECT id,item,status,created_at FROM orders WHERE id=?',(order_id,)).fetchone()
    if not row: raise HTTPException(404,'Заявка не найдена')
    return dict(row) | {'number':f'MOCK-{row["id"]:06}'}
@app.patch('/orders/{order_id}')
def set_order_status(order_id:int, body:OrderStatus):
    if body.status not in ('CREATED','APPROVED','ORDERED','COMPLETED','CANCELLED'): raise HTTPException(400,'Недопустимый статус')
    log('set_order_status')
    with db() as c:
        cursor=c.execute('UPDATE orders SET status=? WHERE id=?',(body.status,order_id))
        if cursor.rowcount==0: raise HTTPException(404,'Заявка не найдена')
    return get_order(order_id)
@app.get('/history')
def request_history():
    with db() as c: return [dict(row) for row in c.execute('SELECT id,operation,created_at FROM request_log ORDER BY id DESC LIMIT 100')]
