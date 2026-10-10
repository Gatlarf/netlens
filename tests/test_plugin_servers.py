"""The `servers` settings field: one row per server, secrets kept per row, older settings carried over."""

import pytest

from app.plugins.contract import ContractError, clean_config, migrate_servers, missing_required, validate_manifest
from app.plugins.service import merge_config, public_server
from app.plugins.registry import Plugin


def manifest(**field):
    base = {"key": "servers", "type": "servers", "label": "Servers", "required": True,
            "columns": [{"key": "host", "label": "Address", "required": True}, {"key": "token", "label": "Token", "type": "password", "required": True}]}
    base.update(field)
    return validate_manifest({"id": "demo", "name": "Demo", "version": "1.0.0", "api_version": 1, "kind": "hypervisor", "config": [base]})


def plugin(m):
    return Plugin(id="demo", manifest=m, builtin=False, path=None, problem=None) if "path" in Plugin.__dataclass_fields__ else None


def test_the_first_column_must_be_host_and_columns_are_checked():
    with pytest.raises(ContractError):
        manifest(columns=[{"key": "token"}])
    with pytest.raises(ContractError):
        manifest(columns=[])
    with pytest.raises(ContractError):
        manifest(columns=[{"key": "host"}, {"key": "id"}])
    assert manifest()["config"][0]["columns"][1]["secret"] is True


def test_rows_are_cleaned_and_empty_lines_dropped():
    m = manifest()
    out = clean_config(m, {"servers": [{"host": " a ", "token": "t1"}, {"host": "", "token": ""}, {"host": "b", "token": "t2", "extra": "x"}]})["servers"]
    assert [(r["host"], r["token"]) for r in out] == [("a", "t1"), ("b", "t2")]
    assert len({r["id"] for r in out}) == 2 and all("extra" not in r for r in out)
    with pytest.raises(ContractError):
        clean_config(m, {"servers": "not a list"})
    with pytest.raises(ContractError):
        clean_config(m, {"servers": [{"host": str(i)} for i in range(21)]})


def test_a_secret_left_empty_keeps_the_saved_one_of_the_same_row():
    m = manifest()
    saved = clean_config(m, {"servers": [{"id": "x", "host": "a", "token": "t1"}, {"id": "y", "host": "b", "token": "t2"}]})
    # the second row is removed, the first one is edited without retyping its token, a new row has a token of its own
    edited = clean_config(m, {"servers": [{"id": "x", "host": "a2", "token": ""}, {"host": "c", "token": "t3"}]}, saved)["servers"]
    assert [(r["host"], r["token"]) for r in edited] == [("a2", "t1"), ("c", "t3")]
    field = m["config"][0]
    assert public_server(field, edited[0]) == {"id": "x", "host": "a2", "token_set": True}


def test_required_is_checked_per_row():
    m = manifest()
    assert missing_required(m, {"servers": []}) == ["Servers"]
    assert missing_required(m, {"servers": [{"id": "a", "host": "h", "token": ""}]}) == ["Servers 1: Token"]
    assert missing_required(m, {"servers": [{"id": "a", "host": "h", "token": "t"}]}) == []


def test_older_settings_become_rows():
    m = manifest(legacy={"split": ",", "map": {"host": "servers", "token": "tokens"}})
    field = m["config"][0]
    rows = migrate_servers(field, {"servers": "http://a:1, http://b:2", "tokens": "t1,t2"})
    assert [(r["host"], r["token"]) for r in rows] == [("http://a:1", "t1"), ("http://b:2", "t2")]
    one = migrate_servers(field, {"servers": "http://a:1 http://b:2", "tokens": "same"})
    assert [r["token"] for r in one] == ["same", "same"]          # one token for all servers
    assert migrate_servers(field, {}) == []
    pair = manifest(columns=[{"key": "host"}, {"key": "lan"}], legacy={"split": " ", "map": {"host": "hosts"}, "pair": {"sep": "=", "column": "lan"}})["config"][0]
    assert migrate_servers(pair, {"hosts": "http://127.0.0.1:2375=192.168.0.5 http://10.0.0.9:2375"}) == [
        {"id": "s1", "host": "http://127.0.0.1:2375", "lan": "192.168.0.5"}, {"id": "s2", "host": "http://10.0.0.9:2375"}]
