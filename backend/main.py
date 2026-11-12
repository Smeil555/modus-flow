"""Public MODUS FLOW gateway. All operations persistence is behind local HTTP."""
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

app = FastAPI(title='MODUS FLOW', docs_url=None, redoc_url=None, openapi_url=None)
DATA_URL = 'http://127.0.0.1:8002'
REQUEST_HEADERS = {'accept', 'content-type', 'cookie', 'origin', 'x-csrf-token', 'range', 'if-range', 'access-control-request-method', 'access-control-request-headers'}
RESPONSE_HEADERS = {
    'cache-control', 'content-type', 'content-disposition', 'content-range', 'accept-ranges',
    'set-cookie', 'retry-after', 'vary', 'access-control-allow-origin', 'access-control-allow-credentials',
    'access-control-allow-methods', 'access-control-allow-headers', 'access-control-max-age', 'x-content-type-options', 'x-frame-options', 'referrer-policy',
}


def error(status, message):
    return JSONResponse({'detail': message}, status_code=status, headers={'Cache-Control': 'no-store'})


def gateway_headers(request):
    headers = {name: value for name, value in request.headers.items() if name in REQUEST_HEADERS}
    headers['x-modus-service-token'] = os.environ.get('DATA_SERVICE_TOKEN', '')
    if request.client:
        try:
            headers['x-modus-client-ip'] = str(ipaddress.ip_address(request.client.host))
        except ValueError:
            pass
    return headers


def required_permission(path, method):
    if re.fullmatch(r'users/\d+(?:/(?:password|permissions|grants))?', path) or (path == 'users' and method == 'POST'):
        return 'SUPER_ADMIN'
    if method == 'POST' and re.fullmatch(r'departments(?:/\d+)?', path):
        return 'departments.manage'
    if re.fullmatch(r'routing-rules(?:/\d+)?', path):
        return 'categories.manage'
    if method == 'POST' and re.fullmatch(r'tickets/\d+/implementation', path):
        return 'SUPER_ADMIN'
    return {
        'admin/settings': 'SUPER_ADMIN', 'admin/data': 'data.read', 'admin/audit': 'audit.read',
        'analytics': 'analytics.read', 'integration/events': 'integration.read',
        'integration/mock-history': 'SUPER_ADMIN',
    }.get(path)


@app.get('/health')
async def health(request: Request):
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=2) as client:
            response = await client.get(DATA_URL + '/health', headers=gateway_headers(request))
        if response.status_code == 200 and response.json() == {'service': 'modus-data', 'status': 'ok'}:
            return {'service': 'modus-backend', 'status': 'ok', 'data_service': 'ok'}
    except (httpx.HTTPError, ValueError):
        pass
    return error(503, 'Сервис данных недоступен')


async def forward(request, target, permission=None):
    headers = gateway_headers(request)
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(30, connect=2)) as client:
            if permission:
                identity = await client.get(DATA_URL + '/identity', headers=headers)
                if identity.status_code != 200:
                    return public_response(identity)
                user = identity.json()
                if user['role'] != 'SUPER_ADMIN' and (
                    permission == 'SUPER_ADMIN' or permission not in user.get('permissions', [])
                ):
                    return error(403, 'Недостаточно прав')
            content = bytearray()
            async for chunk in request.stream():
                if len(content) + len(chunk) > 12_000_000:
                    return error(413, 'Запрос слишком большой')
                content.extend(chunk)
            url = httpx.URL(DATA_URL + target).copy_with(query=request.scope['query_string'])
            upstream = await client.send(httpx.Request(request.method, url, headers=headers, content=bytes(content)))
        return public_response(upstream)
    except httpx.TimeoutException:
        return error(504, 'Сервис данных не ответил вовремя')
    except httpx.HTTPError:
        return error(503, 'Сервис данных недоступен')


def public_response(upstream):
    response = Response(upstream.content, status_code=upstream.status_code)
    for name, value in upstream.headers.multi_items():
        if name in RESPONSE_HEADERS:
            response.headers.append(name, value)
    return response


@app.api_route('/api/{path:path}', methods=['GET', 'POST', 'HEAD', 'OPTIONS'])
async def api(request: Request, path: str):
    if any(part in ('.', '..') for part in path.split('/')) or '\\' in path:
        return error(404, 'Маршрут не найден')
    permission = None if request.method == 'OPTIONS' else required_permission(path, request.method)
    return await forward(request, '/api/' + quote(path, safe='/'), permission)


@app.get('/docs')
@app.get('/openapi.json')
async def documentation(request: Request):
    return await forward(request, request.url.path)


frontend_dir = 'frontend-react/dist' if Path('frontend-react/dist/index.html').exists() else 'frontend'
app.mount('/', StaticFiles(directory=frontend_dir, html=True), name='frontend')
