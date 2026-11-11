"""Supervise the local MODUS FLOW processes from a single console."""
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import webbrowser

import httpx
import uvicorn

HOST = '127.0.0.1'
SERVICES = {
    'data': ('backend.data_server:app', 8002, 'modus-data'),
    'backend': ('backend.main:app', 8000, 'modus-backend'),
    'mock': ('mock_1c.main:app', 8001, None),
}


def child(name):
    app, port, _ = SERVICES[name]
    server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=port, proxy_headers=False))

    def wait_for_shutdown():
        sys.stdin.buffer.read()
        server.should_exit = True

    threading.Thread(target=wait_for_shutdown, daemon=True).start()
    server.run()


def healthy(client, name, token=None):
    _, port, service = SERVICES[name]
    headers = {'X-Modus-Service-Token': token} if token else {}
    try:
        response = client.get(f'http://{HOST}:{port}/health', headers=headers)
        payload = response.json()
        return response.status_code == 200 and payload.get('status') == 'ok' and (
            service is None or payload.get('service') == service
        )
    except (httpx.HTTPError, ValueError, AttributeError):
        return False


def wait_ready(client, name, process, token):
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError(f'{name} exited during startup (code {process.returncode})')
        if healthy(client, name, token if name == 'data' else None):
            return
        time.sleep(.25)
    raise RuntimeError(f'{name} did not become ready on port {SERVICES[name][1]}')


def ensure_ports_available():
    for name, (_, port, _) in SERVICES.items():
        with socket.socket() as probe:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                probe.bind((HOST, port))
            except OSError as exc:
                raise RuntimeError(f'Port {port} ({name}) is occupied. Stop its owner and try again.') from exc


def stop(processes):
    for process in reversed(processes):
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def supervise():
    processes = []
    try:
        with httpx.Client(trust_env=False, timeout=1) as client:
            if healthy(client, 'backend'):
                print('MODUS FLOW is already running.')
                webbrowser.open('http://localhost:8000')
                return 0
            ensure_ports_available()
            for args in (('scripts.prepare_database',), ('alembic', 'upgrade', 'head'),
                         ('scripts.seed', '--prompt-admin')):
                subprocess.run([sys.executable, '-m', *args], check=True)
            token = secrets.token_urlsafe(48)
            environment = dict(os.environ, DATA_SERVICE_TOKEN=token)
            environment.pop('INITIAL_ADMIN_PASSWORD', None)
            for name in SERVICES:
                process = subprocess.Popen(
                    [sys.executable, '-m', 'scripts.run_services', name],
                    stdin=subprocess.PIPE, env=environment,
                    creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0),
                )
                processes.append(process)
                wait_ready(client, name, process, token)
            print('MODUS FLOW is ready. Press Ctrl+C in this window to stop its services.', flush=True)
            webbrowser.open('http://localhost:8000')
            while all(process.poll() is None for process in processes):
                time.sleep(.5)
            raise RuntimeError('A MODUS FLOW service stopped unexpectedly.')
    except KeyboardInterrupt:
        return 0
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(f'MODUS FLOW startup error: {exc}', file=sys.stderr)
        return 1
    finally:
        stop(processes)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        child(sys.argv[1])
    else:
        raise SystemExit(supervise())
