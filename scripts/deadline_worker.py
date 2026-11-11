"""Run alongside the API; use --once for scheduled execution or verification."""
import argparse, time
from backend.deadlines import generate_reminders
from backend.models import Session

parser=argparse.ArgumentParser(); parser.add_argument('--once',action='store_true'); parser.add_argument('--interval',type=int,default=60)
args=parser.parse_args()
if args.interval<10: raise SystemExit('Интервал должен быть не менее 10 секунд')
while True:
    with Session() as db: count=generate_reminders(db)
    print(f'Создано уведомлений: {count}',flush=True)
    if args.once: break
    time.sleep(args.interval)
