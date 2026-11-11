"""Copy the previous local SQLite database while preserving account and ticket IDs."""
import os
import sqlite3
from pathlib import Path


def main():
    source = Path('modus.db')
    destination = Path('operations.db')
    if os.getenv('DATABASE_URL') or not source.is_file() or destination.exists():
        return
    temporary = destination.with_suffix('.db.migrating')
    with temporary.open('xb'):
        pass
    try:
        from contextlib import closing

        with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True)) as old:
            with closing(sqlite3.connect(temporary)) as new:
                old.backup(new)
        temporary.rename(destination)
    finally:
        temporary.unlink(missing_ok=True)
    print('Copied modus.db to operations.db.')


if __name__ == '__main__':
    main()
