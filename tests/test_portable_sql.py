"""The application code sticks to the SQL subset in docs/SQL-RULES.md, so that a second database engine can run it unchanged.

Modules that are SQLite files by nature are exempt (and are the work list for a second engine); everywhere else a SQLite-only construct fails the test.
A line can opt out with the comment `# portable-ok` and a reason.
"""
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
SQLITE_BY_NATURE = {"db.py", "dbengine.py", "tsdb.py", "backup.py", "dbmaint.py"}

RULES = [
    (r"\bINSERT\s+OR\s+(REPLACE|IGNORE)\b|\bREPLACE\s+INTO\b", "use INSERT ... ON CONFLICT (...) DO UPDATE / DO NOTHING"),
    (r"\.lastrowid\b", "use db.insert_id(conn, sql, params)"),
    (r"\bCOLLATE\s+NOCASE\b", "use LOWER(x)"),
    (r"\bPRAGMA\b", "engine administration belongs in app/dbengine.py"),
    (r"\bsqlite_(master|schema|sequence)\b", "engine administration belongs in app/dbengine.py"),
    (r"\bVACUUM\b(?!\s*\))", "engine administration belongs in app/dbengine.py"),
    (r"\.backup\(|\.executescript\(|\bATTACH\s+DATABASE\b", "engine administration belongs in app/dbengine.py"),
    (r"(?<![.\w])(datetime|date|strftime|julianday)\(\s*['\"]", "compute the time in Python (db.ago / db.utcnow) and pass it as a parameter"),
    (r"\b(MIN|MAX)\(\s*[^()]+,[^()]*\)", "two-argument MIN/MAX is SQLite only: use CASE WHEN"),
    (r"\bsqlite3\.(Error|IntegrityError|OperationalError|DatabaseError|ProgrammingError)\b", "catch db.Error / db.IntegrityError from app.db"),
    (r"\b(AUTOINCREMENT|WITHOUT\s+ROWID|json_extract|json_each|group_concat|ifnull|GLOB)\b|\browid\b", "SQLite-only function or keyword"),
]


def source_files():
    return [p for p in sorted(APP.rglob("*.py")) if p.name not in SQLITE_BY_NATURE or p.parent != APP]


def test_application_code_uses_only_portable_sql():
    found = []
    for path in source_files():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            text = line.strip()
            if text.startswith("#") or "portable-ok" in line:
                continue
            for pattern, advice in RULES:
                if re.search(pattern, line):
                    found.append(f"{path.relative_to(APP.parent)}:{number}: {advice}: {text[:110]}")
    assert not found, "SQLite-only constructs (see docs/SQL-RULES.md):\n" + "\n".join(found)


def test_the_exempt_modules_exist():
    assert all((APP / name).is_file() for name in SQLITE_BY_NATURE)
