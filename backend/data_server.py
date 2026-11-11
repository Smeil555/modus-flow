"""Local HTTP entry point for the service that owns operations.db."""
import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .deadlines import generate_reminders
from .models import Session, User
from .operations_api import app as operations, current


@operations.post('/deadlines/run', include_in_schema=False)
def check_deadlines():
    with Session() as db:
        return {'created': generate_reminders(db)}


async def run_deadlines(stop):
    while not stop.is_set():
        try:
            await asyncio.to_thread(check_deadlines)
        except Exception:
            logging.getLogger(__name__).exception('Deadline reminder check failed')
        try:
            await asyncio.wait_for(stop.wait(), timeout=60)
        except TimeoutError:
            pass


@asynccontextmanager
async def lifespan(app):
    stop = asyncio.Event()
    task = asyncio.create_task(run_deadlines(stop))
    try:
        yield
    finally:
        stop.set()
        await task


operations.router.lifespan_context = lifespan


@operations.get('/health')
def health():
    try:
        with Session() as db:
            db.scalar(select(User.id).limit(1))
    except Exception:
        return JSONResponse({'service': 'modus-data', 'status': 'unavailable'}, status_code=503)
    return {'service': 'modus-data', 'status': 'ok'}


@operations.get('/identity', include_in_schema=False)
def identity(principal=Depends(current)):
    return {'role': principal.role, 'permissions': list(principal.permissions)}


async def app(scope, receive, send):
    if scope['type'] != 'http':
        await operations(scope, receive, send)
        return
    headers = dict(scope['headers'])
    key = os.getenv('DATA_SERVICE_TOKEN', '').encode()
    peer = scope.get('client')
    if len(key) < 32 or not peer or peer[0] not in ('127.0.0.1', '::1') or not hmac.compare_digest(
        headers.get(b'x-modus-service-token', b''), key
    ):
        await JSONResponse({'detail': 'Unauthorized service request'}, status_code=401)(scope, receive, send)
        return
    original_ip = headers.get(b'x-modus-client-ip')
    if original_ip:
        scope = dict(scope, client=(original_ip.decode('ascii'), 0))
    await operations(scope, receive, send)
