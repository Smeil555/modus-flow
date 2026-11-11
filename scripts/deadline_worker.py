"""Trigger deadline reminders through Data Service for maintenance."""
import argparse
import os
import time

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval', type=int, default=60)
    args = parser.parse_args()
    if args.interval < 10:
        parser.error('interval must be at least 10 seconds')
    token = os.environ.get('DATA_SERVICE_TOKEN')
    if not token:
        parser.error('DATA_SERVICE_TOKEN is required for a manual service request')
    with httpx.Client(trust_env=False, timeout=30, headers={'X-Modus-Service-Token': token}) as client:
        while True:
            response = client.post('http://127.0.0.1:8002/deadlines/run')
            response.raise_for_status()
            print(response.json(), flush=True)
            if args.once:
                break
            time.sleep(args.interval)


if __name__ == '__main__':
    main()
