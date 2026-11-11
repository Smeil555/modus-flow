"""Consistent SQLite snapshot; attachment files must be backed up separately."""
import argparse, sqlite3
from pathlib import Path
from backend.models import engine

def backup_database(source:Path,destination:Path):
    if not source.is_file(): raise ValueError('База данных не найдена')
    if destination.exists(): raise ValueError('Файл резервной копии уже существует')
    destination.parent.mkdir(parents=True,exist_ok=True)
    created=False
    try:
        with destination.open('xb'): created=True
        with sqlite3.connect(f'file:{source.resolve().as_posix()}?mode=ro',uri=True) as src, sqlite3.connect(destination) as dst: src.backup(dst)
    except Exception:
        if created: destination.unlink(missing_ok=True)
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Создать резервную копию SQLite')
    parser.add_argument('destination',type=Path); args=parser.parse_args()
    if engine.dialect.name!='sqlite' or not engine.url.database or engine.url.database==':memory:': raise SystemExit('Нужна файловая SQLite')
    backup_database(Path(engine.url.database),args.destination)
    print('Резервная копия создана:',args.destination)
