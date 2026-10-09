import hashlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "plugin-index" / "tools"
sys.path.insert(0, str(TOOLS))


def load(name):
    spec = importlib.util.spec_from_file_location(f"idxtool_{name}", TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses need the module to be registered
    spec.loader.exec_module(module)
    return module


scan = load("static_scan")
build = load("build_index")
immutable = load("check_immutable")
gate = load("review_gate")
verify = load("verify_release")
check = load("check_plugin")

GOOD_PY = "def test(config):\n    return {}\ndef fetch(config):\n    return {'nodes': [], 'clients': []}\n"


def make_zip(py=GOOD_PY, plugin_id="demo", version="1.0.0", kind="topology", extra=None):
    manifest = {"id": plugin_id, "name": "Demo", "version": version, "api_version": 1, "kind": kind}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plugin.json", json.dumps(manifest))
        z.writestr("plugin.py", py)
        for name, content in (extra or {}).items():
            z.writestr(name, content)
    return buf.getvalue()


def rules(source):
    return sorted({f.rule for f in scan.scan_source(source)})


# ------------------------------------------------------------------ static scan
@pytest.mark.parametrize("source,expected", [
    ("eval('1')", ["dynamic-code"]), ("exec('x=1')", ["dynamic-code"]), ("__import__('os')", ["dynamic-code"]), ("import importlib", ["dynamic-code"]),
    ("import subprocess\nsubprocess.run(['ls'])", ["subprocess"]), ("import os\nos.system('ls')", ["subprocess"]),
    ("import ctypes", ["native-code"]), ("import multiprocessing", ["native-code"]), ("import os\nos.fork()", ["native-code"]),
    ("import sqlite3", ["database"]), ("import pickle", ["serialization"]), ("from marshal import loads", ["serialization"]),
    ("open('/etc/passwd')", ["file-system"]), ("open('x', 'w')", ["file-system"]), ("import shutil\nshutil.rmtree('x')", ["file-system"]),
    ("import os\nx = os.environ['A']", ["environment"]), ("import os\nos.getenv('A')", ["environment"]),
    ("import base64\nbase64.b64decode('x')", ["obfuscation"]), ("import socket\ns = socket.socket()\ns.listen()", ["network-server"]),
    ("U = 'https://evil.example.org/x'", ["external-url"]), ("U = 'https://tracker.cn/x'", ["external-url"]),
])
def test_risky_code_is_flagged(source, expected):
    assert set(expected) <= set(rules(source))


@pytest.mark.parametrize("source", [
    GOOD_PY,
    "import urllib.request, json, ssl, socket, re, base64.__name__ if False else None" if False else "import urllib.request, json, ssl, socket, re",
    "U = 'http://192.168.0.1:8080/x'", "U = 'https://10.0.0.5/x'", "U = 'http://example.com/x'", "U = 'http://router.lan/x'", "U = 'http://schemas.upnp.org/x'",
    "def f(config):\n    return open_page(config['host'])",  # a function merely named like open
])
def test_normal_plugin_code_is_clean(source):
    assert scan.scan_source(source) == []


def test_levels_and_allow_list():
    flags = scan.scan_source("import subprocess\nimport os\nos.environ\nopen('x')\n")
    assert {f.rule: f.level for f in flags} == {"subprocess": "error", "environment": "warn", "file-system": "warn"}
    assert [f.rule for f in scan.blocking(flags)] == ["subprocess"]
    assert scan.blocking(flags, ["subprocess"]) == []  # a reviewer allowed it for this version
    assert "subprocess" in str(flags[-1]) or any("subprocess" in str(f) for f in flags)
    with pytest.raises(ValueError, match="syntax error"):
        scan.scan_source("def (:")


def test_scan_files_only_reads_python(tmp_path):
    flags = scan.scan_files({"plugin.py": b"import subprocess\n", "helper.py": b"eval('1')", "data.json": b"{not python"})
    assert {f.file for f in flags} == {"plugin.py", "helper.py"}


# ------------------------------------------------------------------ building the index
def entry(plugin_id="demo", sha="a" * 64, version="1.0.0", **extra):
    return {"id": plugin_id, "name": "Demo", "kind": "topology", "author": "x", "releases": [{"version": version, "download_url": f"https://github.com/x/{plugin_id}/releases/download/v{version}/p.zip", "sha256": sha, "api_version": 1}], **extra}


def write_index(tmp, entries, reviews=()):
    (tmp / "plugins").mkdir(parents=True, exist_ok=True)
    (tmp / "reviews").mkdir(parents=True, exist_ok=True)
    for e in entries:
        (tmp / "plugins" / f"{e['id']}.json").write_text(json.dumps(e))
    for r in reviews:
        (tmp / "reviews" / f"{r['id']}.json").write_text(json.dumps(r))
    return tmp


def test_reviews_apply_to_the_exact_version_and_checksum(tmp_path):
    index = write_index(tmp_path, [entry("a1", "a" * 64), entry("b2", "b" * 64), entry("c3", "c" * 64)], [
        {"id": "a1", "reviews": [{"version": "1.0.0", "sha256": "A" * 64, "level": "verified", "reviewer": "bert", "date": "2026-10-09", "tested_on": ["X1"], "notes": "ok"}]},
        {"id": "b2", "reviews": [{"version": "1.0.0", "sha256": "0" * 64, "level": "verified", "reviewer": "bert"}]},  # a different file than the release
        {"id": "c3", "reviews": [{"version": "9.9.9", "sha256": "c" * 64, "level": "reviewed", "reviewer": "bert"}]},  # another version
    ])
    doc, problems = build.merge(index)
    assert problems == []
    levels = {p["id"]: p["releases"][0]["review"] for p in doc["plugins"]}
    assert levels["a1"] == {"level": "verified", "reviewer": "bert", "date": "2026-10-09", "tested_on": ["X1"], "notes": "ok"}  # checksum case does not matter
    assert levels["b2"] == {"level": "community"} and levels["c3"] == {"level": "community"}


def test_authors_cannot_grant_themselves_a_level(tmp_path):
    e = entry("sneaky")
    e["releases"][0]["review"] = {"level": "verified", "reviewer": "me"}
    doc, problems = build.merge(write_index(tmp_path, [e]))
    assert problems == [] and doc["plugins"][0]["releases"][0]["review"] == {"level": "community"}


def test_bad_sources_are_reported(tmp_path):
    index = write_index(tmp_path, [entry("good"), {**entry("nohost"), "releases": [{**entry()["releases"][0], "download_url": "https://evil.example/p.zip"}]}],
                        [{"id": "ghost", "reviews": []}])
    (index / "plugins" / "broken.json").write_text("{nope")
    (index / "plugins" / "wrongname.json").write_text(json.dumps(entry("other")))
    doc, problems = build.merge(index)
    text = "\n".join(problems)
    assert "broken.json: not valid JSON" in text and "wrongname.json: the id 'other' must equal the file name" in text
    assert "nohost.json: the entry is not valid" in text and "reviews/ghost.json: there is no plugin" in text
    assert [p["id"] for p in doc["plugins"]] == ["good"]


def test_output_is_deterministic_and_sorted(tmp_path):
    index = write_index(tmp_path, [entry("zz"), entry("aa")])
    doc, _ = build.merge(index)
    assert [p["id"] for p in doc["plugins"]] == ["aa", "zz"] and build.render(doc) == build.render(build.merge(index)[0])
    assert doc["schema"] == 1


# ------------------------------------------------------------------ immutability, review gate
def test_published_versions_are_immutable():
    old = entry("demo", "a" * 64)
    ok = {**entry("demo", "a" * 64), "description": "new text"}
    assert immutable.compare(old, ok) == []
    new_version = {**old, "releases": old["releases"] + [entry("demo", "b" * 64, "1.1.0")["releases"][0]]}
    assert immutable.compare(old, new_version) == []
    changed = entry("demo", "b" * 64)
    assert "sha256 changed" in immutable.compare(old, changed)[0]
    moved = {**old, "releases": [{**old["releases"][0], "download_url": "https://github.com/x/other.zip"}]}
    assert "download_url changed" in immutable.compare(old, moved)[0]
    assert "removed" in immutable.compare(old, {**old, "releases": []})[0]


@pytest.mark.parametrize("changed,author,approvers,ok", [
    (["plugin-index/plugins/x.json"], "stranger", [], True),  # entries are open to everyone
    (["plugin-index/reviews/x.json"], "stranger", [], False),
    (["plugin-index/reviews/x.json"], "Gatlarf", [], True),  # the author is a trusted reviewer
    (["plugin-index/reviews/x.json"], "stranger", ["Reviewer1"], True),  # approved by one
    (["plugin-index/reviews/x.json"], "stranger", ["nobody"], False),
    (["plugin-index/REVIEWERS"], "stranger", [], False),
    (["app/main.py"], "stranger", [], True),
])
def test_review_gate(changed, author, approvers, ok):
    assert (gate.check(changed, author, approvers, ["gatlarf", "reviewer1"]) == []) is ok


# ------------------------------------------------------------------ verifying releases
class Downloads:
    def __init__(self, data):
        self.data = data

    def __call__(self, url, *, max_bytes, headers=None, timeout=20.0):
        return 200, self.data, {}


def verified(py=GOOD_PY, allowed=(), **kw):
    data = make_zip(py, **{k: v for k, v in kw.items() if k in ("plugin_id", "version", "kind", "extra")})
    e = entry("demo", hashlib.sha256(data).hexdigest())
    return verify.verify_release(e, e["releases"][0], list(allowed), getter=Downloads(kw.get("served", data)))


def test_a_good_release_passes():
    errors, report = verified()
    assert errors == [] and report == []


def test_verification_failures():
    assert "does not match the checksum" in verified(served=b"other")[0][0]
    assert "plugin.json says id 'wrong'" in verified(plugin_id="wrong")[0][0]
    assert "plugin.json says version '2.0.0'" in verified(version="2.0.0")[0][0]
    assert "plugin.json says kind 'hypervisor'" in verified(kind="hypervisor")[0][0]
    assert "not installable" in verified(served=b"not a zip")[0][0] or "does not match" in verified(served=b"not a zip")[0][0]
    bad = entry("demo")
    bad["releases"][0]["download_url"] = "https://evil.example/x.zip"
    assert "not valid for the official index" in verify.verify_release(bad, bad["releases"][0], [])[0][0]


def test_blocking_code_fails_unless_a_reviewer_allowed_that_rule():
    risky = GOOD_PY + "\nimport subprocess\n"
    errors, report = verified(risky)
    assert len(errors) == 1 and "subprocess" in errors[0] and "allow it in the review" in errors[0] and any("subprocess" in r for r in report)
    errors, report = verified(risky, allowed=["subprocess"])
    assert errors == [] and report  # still reported, no longer blocking
    assert verified(GOOD_PY + "\nx = open('f')\n")[0] == []  # a note does not block


def test_extra_python_files_are_scanned_too():
    errors, _ = verified(extra={"helper.py": "eval('1')"})
    assert errors and "helper.py" in errors[0]


# ------------------------------------------------------------------ the author's checker
def run_check(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["check_plugin.py", *map(str, args)])
    code = check.main()
    return code, capsys.readouterr().out


def test_author_checker_on_a_folder(tmp_path, monkeypatch, capsys):
    (tmp_path / "plugin.json").write_text(json.dumps({"id": "demo", "name": "Demo", "version": "1.0.0", "api_version": 1, "kind": "topology"}))
    (tmp_path / "plugin.py").write_text(GOOD_PY)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("eval('1')")  # tests are not part of the package
    code, out = run_check(monkeypatch, capsys, tmp_path)
    assert code == 0 and "all checks passed" in out and "2 file(s)" in out


def test_author_checker_reports_problems(tmp_path, monkeypatch, capsys):
    (tmp_path / "plugin.json").write_text(json.dumps({"id": "demo", "name": "Demo", "version": "1.0.0", "api_version": 1, "kind": "topology"}))
    (tmp_path / "plugin.py").write_text(GOOD_PY + "\nimport subprocess\n")
    code, out = run_check(monkeypatch, capsys, tmp_path)
    assert code == 1 and "blocking code" in out and "subprocess" in out
    (tmp_path / "plugin.py").write_text("def broken(")
    code, out = run_check(monkeypatch, capsys, tmp_path)
    assert code == 1 and "syntax error" in out


def test_author_checker_validates_recorded_output_and_runs_the_plugin(tmp_path, monkeypatch, capsys):
    (tmp_path / "plugin.json").write_text(json.dumps({"id": "demo", "name": "Demo", "version": "1.0.0", "api_version": 1, "kind": "topology",
                                                      "config": [{"key": "host", "type": "text", "label": "Host"}]}))
    (tmp_path / "plugin.py").write_text("def test(config):\n    return {'message': 'hi ' + config['host']}\ndef fetch(config):\n    return {'nodes': [{'mac': 'aa:bb:cc:00:00:01', 'role': 'gateway'}], 'clients': []}\n")
    good = tmp_path / "out.json"
    good.write_text(json.dumps({"nodes": [{"mac": "aa:bb:cc:00:00:01"}], "clients": []}))
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"host": "r.lan"}))
    code, out = run_check(monkeypatch, capsys, tmp_path, "--output", good, "--config", cfg)
    assert code == 0 and "output file follows the topology contract" in out and "test() ran: hi r.lan" in out and "1 nodes, 0 clients" in out
    good.write_text(json.dumps({"nodes": [{"mac": "nonsense"}]}))
    code, out = run_check(monkeypatch, capsys, tmp_path, "--output", good)
    assert code == 1 and "output file" in out and "nodes[0].mac" in out


def test_author_checker_on_the_template_and_the_example_zip(monkeypatch, capsys):
    template = Path(__file__).resolve().parents[1] / "plugin-index" / "template"
    code, out = run_check(monkeypatch, capsys, template, "--output", template / "tests" / "sample_output.json")
    assert code == 0, out
    from app.plugins.example import build_example_zip

    zip_path = Path("/tmp") / "idx_example.zip"
    zip_path.write_bytes(build_example_zip())
    assert run_check(monkeypatch, capsys, zip_path)[0] == 0


# ------------------------------------------------------------------ the real index in this repository
def test_the_repository_index_is_valid_and_up_to_date():
    doc, problems = build.merge()
    assert problems == []
    on_disk = (build.INDEX_DIR / "index.json").read_text(encoding="utf-8")
    assert on_disk == build.render(doc), "plugin-index/index.json is stale: run python plugin-index/tools/build_index.py"
    ids = {p["id"]: p for p in doc["plugins"]}
    assert {"proxmox", "asus", "example-router"} <= set(ids) and ids["proxmox"]["builtin"] and ids["asus"]["builtin"]
    assert ids["example-router"]["releases"][0]["review"]["level"] == "reviewed"


def test_the_repository_index_is_accepted_by_netlens():
    from app.plugins import index as idx

    entries, skipped = idx.parse_index(json.loads((build.INDEX_DIR / "index.json").read_text()), official=True)
    assert skipped == 0 and {e["id"] for e in entries} >= {"proxmox", "asus", "example-router"}
