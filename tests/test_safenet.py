"""The outbound-address guard (SSRF) and the safe XML parser."""

import socket
import urllib.error
import urllib.request

import pytest

from app import safenet, safexml


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://169.254.0.1/", "http://[fe80::1]/", "http://0.0.0.0/", "http://224.0.0.1/", "http://100.100.100.200/",
                                 "http://metadata.google.internal/computeMetadata/v1/", "http://[::ffff:169.254.169.254]/", "http://[fd00:ec2::254]/", "http://METADATA.GOOGLE.INTERNAL./"])
def test_the_metadata_service_and_link_local_addresses_are_refused(url):
    with pytest.raises(safenet.BlockedAddress):
        safenet.check_url(url)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/", "gopher://127.0.0.1/", "javascript:alert(1)", "//example.com/x", "example.com", "", "http://"])
def test_other_schemes_and_malformed_addresses_are_refused(url):
    with pytest.raises(safenet.BlockedAddress):
        safenet.check_url(url)


def test_credentials_in_the_address_are_refused():
    with pytest.raises(safenet.BlockedAddress, match="user name"):
        safenet.check_url("https://user:secret@hooks.example.com/x")


@pytest.mark.parametrize("url", ["https://hooks.example.com/x", "http://192.168.0.10:8123/api/webhook/abc", "http://127.0.0.1:8080/", "http://localhost:11434/v1", "https://[2001:db8::1]/", "http://10.0.0.5/"])
def test_normal_addresses_stay_allowed(url, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.10", 0))] if a[0] not in ("localhost",) else [(2, 1, 6, "", ("127.0.0.1", 0))])
    assert safenet.check_url(url) == url


def test_a_name_that_points_to_the_metadata_service_is_caught_at_the_moment_of_use(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))])
    with pytest.raises(safenet.BlockedAddress, match="points to"):
        safenet.check_url("https://evil.example.com/hook")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(socket.gaierror("no such host")))
    assert safenet.check_url("https://does-not-exist.example.com/") == "https://does-not-exist.example.com/"       # the request itself fails with its own message


def test_a_redirect_to_a_blocked_address_is_refused():
    handler = safenet._RedirectGuard()
    req = urllib.request.Request("https://allowed.example.com/start")
    with pytest.raises(urllib.error.HTTPError, match="redirect refused"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data/")
    with pytest.raises(urllib.error.HTTPError, match="redirect refused"):
        handler.redirect_request(req, None, 302, "Found", {}, "file:///etc/passwd")


def test_xml_with_a_doctype_or_entities_is_refused_and_plain_xml_is_parsed():
    assert safexml.fromstring("<root><a>1</a></root>").find("a").text == "1"
    assert safexml.fromstring(b'<?xml version="1.0"?><root/>').tag == "root"
    bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><root>&lol2;</root>'
    for bad in (bomb, "<!DOCTYPE x><x/>", "<!doctype x><x/>", '<root><!ENTITY a "b"></root>'):
        with pytest.raises(safexml.UnsafeXml):
            safexml.fromstring(bad)
    with pytest.raises(safexml.UnsafeXml, match="too large"):
        safexml.fromstring("<a>" + "x" * (safexml.MAX_BYTES + 1) + "</a>")
    with pytest.raises(Exception):
        safexml.fromstring("<a>")                                     # not well formed: the parser's own error


# ------------------------------------------------------------------ the guard where it is used
def test_a_device_name_cannot_change_the_address_of_a_webhook_or_break_its_json():
    from app import remediation

    device = {"custom_name": "x/../admin?token=1#", "hostname": None, "primary_ip": "10.0.0.5"}
    run = {"kind": "device_offline", "detail": 'went "offline"\nnext'}
    url = remediation._fill("https://hook.example.com/notify/{device}?e={event}", device, run, "url")
    assert url == "https://hook.example.com/notify/x%2F..%2Fadmin%3Ftoken%3D1%23?e=device_offline"
    body = remediation._fill('{"text": "{device}: {detail}"}', device, run, "json")
    import json
    assert json.loads(body)["text"] == 'x/../admin?token=1#: went "offline"\nnext'                 # still valid JSON, the quotes and the new line cannot get out
    assert remediation._fill("{device}", device, run) == "x/../admin?token=1#"                       # plain text is unchanged


def test_the_places_that_call_out_refuse_the_metadata_service(monkeypatch):
    import urllib.request

    from app import central, engineer, imageupdates, oidc
    from app.hostprobe import credentials
    from app.notify import channels

    def no_network(*a, **k):
        raise AssertionError("a request was sent")

    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    meta = "http://169.254.169.254/latest/meta-data/"
    with pytest.raises(safenet.BlockedAddress):
        channels.http_post(meta, b"{}", {})
    with pytest.raises(oidc.OidcError, match="refused"):
        oidc._fetch(meta)
    with pytest.raises(credentials.CredentialError, match="refused"):
        credentials._post(meta, {}, {})
    with pytest.raises(engineer.EngineerError, match="refused"):
        engineer._post(urllib.request.Request(meta), 5)
    with pytest.raises(central.LinkError, match="refused"):
        central._check_url("http://169.254.169.254")
    assert imageupdates._bearer('Bearer realm="http://169.254.169.254/token",service="x"', "registry.example.com", "lib/x") is None
