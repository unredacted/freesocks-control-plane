"""v2rayN's own data (guiConfigs/guiNDB.db, guiConfigs/guiNConfig.json), for the
Hysteria app checks (scripts/compat/hysteria-apps/v2rayn.sh).

v2rayN has no URL scheme. A subscription added in its window is one SubItem row;
this writes that row (due at once), and v2rayN's own updater then fetches the
raw config and parses it into ProfileItem rows, exactly as for one added by
hand. Choosing a server in the window sets IndexId in guiNConfig.json; this
does the same while the app is stopped.

v2rayn_db.py <data dir> schema           the tables' columns
v2rayn_db.py <data dir> sub <url>        the one test subscription, due now
v2rayn_db.py <data dir> due              the subscription due again (its servers kept)
v2rayn_db.py <data dir> updated          when the app's updater last fetched it
v2rayn_db.py <data dir> profiles         remarks of the subscription's servers
v2rayn_db.py <data dir> select <regex>   make the first matching server active
"""
import json
import re
import sqlite3
import sys

data, command, *args = sys.argv[1:]
DB = f'{data}/guiConfigs/guiNDB.db'
CONFIG = f'{data}/guiConfigs/guiNConfig.json'
SUB_ID = 'fcp-hysteria-check'

db = sqlite3.connect(DB)
db.row_factory = sqlite3.Row


def columns(table):
    return [r['name'] for r in db.execute(f'PRAGMA table_info("{table}")')]


if command == 'schema':
    for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        print(table, columns(table))
elif command == 'sub':
    url = args[0]
    cols = columns('SubItem')
    row = {c: None for c in cols}
    defaults = {
        'Id': SUB_ID,
        'Remarks': 'FCP check',
        'Url': url,
        'Enabled': 1,
        'AutoUpdateInterval': 1,
        'UpdateTime': 0,
        'Sort': 1,
        'ConvertTarget': '',
        'UserAgent': '',
        'Filter': '',
        'MoreUrl': '',
        'PrevProfile': '',
        'NextProfile': '',
        'PreSocksPort': None,
        'Memo': '',
    }
    for c in cols:
        if c in defaults:
            row[c] = defaults[c]
    # Columns this release has that the list above does not know stay NULL,
    # unless the table forbids it: then an empty string or 0 by declared type.
    for r in db.execute('PRAGMA table_info("SubItem")'):
        if r['notnull'] and row[r['name']] is None:
            row[r['name']] = 0 if 'INT' in (r['type'] or '').upper() else ''
    db.execute('DELETE FROM ProfileItem WHERE Subid = ?', (SUB_ID,))
    db.execute('DELETE FROM SubItem WHERE Id = ?', (SUB_ID,))
    db.execute(
        f'INSERT INTO SubItem ({",".join(row)}) VALUES ({",".join("?" * len(row))})',
        list(row.values()),
    )
    db.commit()
elif command == 'due':
    db.execute('UPDATE SubItem SET UpdateTime = 0 WHERE Id = ?', (SUB_ID,))
    db.commit()
elif command == 'updated':
    r = db.execute('SELECT UpdateTime FROM SubItem WHERE Id = ?', (SUB_ID,)).fetchone()
    print(r['UpdateTime'] if r else '')
elif command == 'profiles':
    for r in db.execute('SELECT Remarks FROM ProfileItem WHERE Subid = ?', (SUB_ID,)):
        print(r['Remarks'])
elif command == 'select':
    for r in db.execute('SELECT IndexId, Remarks FROM ProfileItem WHERE Subid = ?', (SUB_ID,)):
        if re.search(args[0], r['Remarks'] or ''):
            config = json.load(open(CONFIG))
            config['IndexId'] = r['IndexId']
            json.dump(config, open(CONFIG, 'w'), indent=2)
            sys.exit(0)
    sys.exit(1)
elif command == 'config-keys':
    print(sorted(json.load(open(CONFIG)).keys()))
else:
    sys.exit(2)
