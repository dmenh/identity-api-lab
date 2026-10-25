"""Portable lab schema export and authenticated encrypted backup/restore.

Run from the application root: python -m scripts.db_tools --help
Never restore into a populated database. The encryption key stays outside the backup.
"""
import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.schema import CreateTable, CreateIndex
from sqlalchemy.dialects import postgresql, mysql, sqlite
from backend.main import Base, Record, Session, engine


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['schema', 'backup', 'restore', 'check'])
    parser.add_argument('--file', help='Output/input file path; required for schema/backup/restore')
    parser.add_argument('--dialect', choices=['postgres', 'mysql', 'sqlite'], default='postgres')
    args = parser.parse_args()
    if args.operation == 'schema':
        if not args.file:
            parser.error('--file is required')
        dialect = {'postgres': postgresql, 'mysql': mysql, 'sqlite': sqlite}[args.dialect].dialect()
        statements = []
        for table in Base.metadata.sorted_tables:
            statements.append(str(CreateTable(table).compile(dialect=dialect)) + ';')
            statements.extend(str(CreateIndex(index).compile(dialect=dialect)) + ';' for index in table.indexes)
        Path(args.file).write_text('\n\n'.join(statements) + '\n', encoding='utf-8')
        print('Schema exported. This release uses the documented portable record-store schema.')
        return
    if args.operation == 'check':
        with Session() as db:
            records = db.scalars(select(Record)).all()
            counts = {}
            for row in records:
                body = json.loads(row.body)
                if row.key != row.kind + ':' + body['id']:
                    raise ValueError('Invalid record identity')
                counts[row.kind] = counts.get(row.kind, 0) + 1
        print(json.dumps({'database': engine.dialect.name, 'records': len(records), 'counts': counts}, indent=2))
        return
    if not args.file:
        parser.error('--file is required')
    key = os.environ.get('LAB_BACKUP_KEY')
    if not key:
        parser.error('Set LAB_BACKUP_KEY to a Fernet key; store it separately from the encrypted backup')
    cipher = Fernet(key.encode())
    if args.operation == 'backup':
        output = Path(args.file)
        if output.exists():
            raise ValueError('Backup destination exists; choose a new filename')
        with Session() as db:
            records = [{'key': r.key, 'kind': r.kind, 'body': r.body} for r in db.scalars(select(Record))]
        payload = {'format': 'identity-api-lab-v1', 'createdAt': datetime.now(timezone.utc).isoformat(), 'records': records}
        output.write_bytes(cipher.encrypt(json.dumps(payload).encode()))
        print(f'Encrypted {len(records)} records. Keep the key separately; test restore before relying on this backup.')
    else:
        payload = json.loads(cipher.decrypt(Path(args.file).read_bytes()))
        if payload.get('format') != 'identity-api-lab-v1':
            raise ValueError('Unsupported backup format')
        Base.metadata.create_all(engine)
        with Session.begin() as db:
            if db.scalar(select(Record.key).limit(1)) is not None:
                raise ValueError('Restore refused: destination database is not empty')
            for item in payload['records']:
                body = json.loads(item['body'])
                if item['key'] != item['kind'] + ':' + body['id']:
                    raise ValueError('Invalid record identity in backup')
                # Moving a database must not revive previously issued sessions or access tokens.
                if item['kind'] in ('session', 'token'):
                    body['revoked'] = True
                db.add(Record(key=item['key'], kind=item['kind'], body=json.dumps(body)))
        print(f"Restored {len(payload['records'])} records; all sessions/tokens revoked. Run check next.")


if __name__ == '__main__':
    main()
