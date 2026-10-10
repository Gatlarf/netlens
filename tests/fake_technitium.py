import http.server
import threading
import json
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple

def _norm(name: str) -> str:
    return name.lower().rstrip('.')

def _ends_with_subdomain(domain: str, zone: str) -> bool:
    d = _norm(domain)
    z = _norm(zone)
    return d == z or d.endswith('.' + z)

def _find_zone_for_ptr(reverse_name: str, zones: Dict[str, Any]) -> Optional[str]:
    rn = _norm(reverse_name)
    for zname in zones:
        if _norm(zname) and rn.endswith('.' + _norm(zname)):
            return zname
    return None

def _ptr_zone_from_ip(ip: str) -> str:
    parts = ip.split('.')
    if len(parts) != 4:
        return ''
    rev = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
    return rev

def _ptr_zone_suffix(reverse_name: str) -> str:
    # /24 zone: drop last label (the host octet)
    labels = reverse_name.split('.')
    if len(labels) >= 4 and labels[-1] == 'arpa' and labels[-2] == 'in-addr':
        return '.'.join(labels[1:])
    return ''

def a_record(name: str, ip: str, comments: str = "") -> Dict[str, Any]:
    return {
        "name": name,
        "type": "A",
        "ttl": 3600,
        "rData": {"ipAddress": ip},
        "comments": comments,
        "disabled": False,
    }

def ptr_record(name: str, target: str, comments: str = "") -> Dict[str, Any]:
    return {
        "name": name,
        "type": "PTR",
        "ttl": 3600,
        "rData": {"ptrName": target},
        "comments": comments,
        "disabled": False,
    }

class FakeTechnitium:
    def __init__(
        self,
        token: str = "tok",
        zones: Optional[Dict[str, Any]] = None,
        cluster: Optional[Dict[str, str]] = None,
        can_modify: bool = True,
        can_delete: bool = True,
        comments_in_records: bool = True,
    ):
        self._token = token
        self._zones: Dict[str, Any] = zones if zones is not None else {}
        self._cluster = cluster
        self._can_modify = can_modify
        self._can_delete = can_delete
        self._comments_in_records = comments_in_records
        self._requests: List[Tuple[str, Dict[str, List[str]], Optional[str]]] = []
        self._lock = threading.Lock()
        self._server: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.url: str = ""

    @property
    def requests(self):
        return self._requests

    @property
    def zones(self):
        return self._zones

    # ------------------------------------------------------------------ internal
    def _log_request(self, path: str, query: Dict[str, List[str]], auth: Optional[str]) -> None:
        self._requests.append((path, query, auth))

    def _auth_ok(self, headers, query: Dict[str, List[str]]) -> bool:
        auth = headers.get('Authorization')
        if auth and auth.startswith('Bearer '):
            return auth[7:] == self._token
        return query.get('token', [''])[0] == self._token

    def _json_response(self, handler: http.server.BaseHTTPRequestHandler, payload: Dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload).encode('utf-8')
        handler.send_response(status)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Content-Length', str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    def _error(self, handler: http.server.BaseHTTPRequestHandler, msg: str) -> None:
        self._json_response(handler, {"status": "error", "errorMessage": msg})

    def _ok(self, handler: http.server.BaseHTTPRequestHandler, response: Dict[str, Any]) -> None:
        self._json_response(handler, {"status": "ok", "response": response})

    def _zone_summary(self, zname: str, zinfo: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": zname,
            "type": zinfo.get("type", "Primary"),
            "internal": False,
            "dnssecStatus": "Unsigned",
            "disabled": zinfo.get("disabled", False),
        }

    def _soa_record(self, zone: str) -> Dict[str, Any]:
        return {
            "name": zone,
            "type": "SOA",
            "ttl": 3600,
            "rData": {
                "primaryNameServer": "dns1",
                "responsiblePerson": f"hostadmin.{zone}",
                "serial": 1,
                "refresh": 900,
                "retry": 300,
                "expire": 604800,
                "minimum": 900,
            },
            "comments": "",
            "disabled": False,
            "dnssecStatus": "Unknown",
        }

    def _ns_record(self, zone: str) -> Dict[str, Any]:
        return {
            "name": zone,
            "type": "NS",
            "ttl": 3600,
            "rData": {"nameServer": "dns1"},
            "comments": "",
            "disabled": False,
            "dnssecStatus": "Unknown",
        }

    # ------------------------------------------------------------------ request handler
    def _make_handler(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # suppress

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                auth = None
                auth_header = self.headers.get('Authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    auth = auth_header[7:]
                elif query.get('token'):
                    auth = query['token'][0]

                outer._log_request(path, query, auth if outer._auth_ok(self.headers, query) else None)

                if not outer._auth_ok(self.headers, query):
                    outer._json_response(self, {"status": "invalid-token", "errorMessage": "Invalid token or session expired."})
                    return

                if path == "/api/zones/list":
                    with outer._lock:
                        zones_list = [outer._zone_summary(z, zinfo) for z, zinfo in outer._zones.items()]
                    outer._ok(self, {"pageNumber": 1, "totalPages": 1, "totalZones": len(zones_list), "zones": zones_list})
                    return

                if path == "/api/zones/records/get":
                    domain = query.get('domain', [''])[0]
                    zone = query.get('zone', [''])[0]
                    list_zone = query.get('listZone', ['false'])[0].lower() == 'true'
                    znorm = _norm(zone)
                    with outer._lock:
                        zinfo = outer._zones.get(znorm)
                    if not zinfo:
                        outer._error(self, f"No such zone was found: {zone}")
                        return
                    records = []
                    with outer._lock:
                        records = list(zinfo.get("records", []))
                    if not list_zone:
                        filtered = [r for r in records if _norm(r.get('name', '')) == _norm(domain)]
                        records_out = filtered
                    else:
                        # add SOA and NS at start
                        soa = outer._soa_record(zone)
                        ns = outer._ns_record(zone)
                        records_out = [soa, ns] + records
                    if not outer._comments_in_records:
                        for r in records_out:
                            r.pop("comments", None)
                    zone_summary = outer._zone_summary(zone, zinfo)
                    outer._ok(self, {"zone": zone_summary, "records": records_out})
                    return

                if path == "/api/zones/records/add":
                    if not outer._can_modify:
                        outer._error(self, "Access was denied to use Zones.Modify")
                        return
                    domain = query.get('domain', [''])[0]
                    zone = query.get('zone', [''])[0]
                    typ = query.get('type', [''])[0].upper()
                    ttl = int(query.get('ttl', ['3600'])[0]) if query.get('ttl') else 3600
                    overwrite = query.get('overwrite', ['false'])[0].lower() == 'true'
                    comments = query.get('comments', [''])[0]
                    znorm = _norm(zone)
                    with outer._lock:
                        zinfo = outer._zones.get(znorm)
                    if not zinfo:
                        outer._error(self, f"No such zone was found: {zone}")
                        return
                    if zinfo.get("type") == "Secondary":
                        outer._error(self, "Cannot add record: the zone is a Secondary zone and is read-only")
                        return
                    if not _ends_with_subdomain(domain, zone):
                        outer._error(self, "Cannot add record: the domain is not part of the zone")
                        return
                    # build record
                    rdata = {}
                    if typ == "A":
                        ip = query.get('ipAddress', [''])[0]
                        if not ip:
                            outer._error(self, "Missing ipAddress")
                            return
                        rdata = {"ipAddress": ip}
                        value = ip
                    elif typ == "AAAA":
                        ip = query.get('ipAddress', [''])[0]
                        if not ip:
                            outer._error(self, "Missing ipAddress")
                            return
                        rdata = {"ipAddress": ip}
                        value = ip
                    elif typ == "PTR":
                        ptr = query.get('ptrName', [''])[0]
                        if not ptr:
                            outer._error(self, "Missing ptrName")
                            return
                        rdata = {"ptrName": ptr}
                        value = ptr
                    elif typ == "CNAME":
                        cname = query.get('cname', [''])[0]
                        if not cname:
                            outer._error(self, "Missing cname")
                            return
                        rdata = {"cname": cname}
                        value = cname
                    else:
                        outer._error(self, f"Unsupported type {typ}")
                        return
                    # check duplicate
                    with outer._lock:
                        exists = any(
                            _norm(r.get('name', '')) == _norm(domain) and
                            r.get('type', '').upper() == typ and
                            ((typ in ('A', 'AAAA') and r.get('rData', {}).get('ipAddress') == value) or
                             (typ == 'PTR' and r.get('rData', {}).get('ptrName') == value) or
                             (typ == 'CNAME' and r.get('rData', {}).get('cname') == value))
                            for r in zinfo.get("records", [])
                        )
                    if exists and not overwrite:
                        outer._error(self, "Cannot add record: the record already exists")
                        return
                    # create record dict
                    rec = {
                        "name": domain,
                        "type": typ,
                        "ttl": ttl,
                        "rData": rdata,
                        "comments": comments,
                        "disabled": False,
                    }
                    with outer._lock:
                        zinfo["records"].append(rec)
                        # handle PTR creation for A
                        if typ == "A" and query.get('ptr', ['false'])[0].lower() == 'true':
                            ip = query.get('ipAddress', [''])[0]
                            rev = _ptr_zone_from_ip(ip)
                            ptr_zone_name = _find_zone_for_ptr(rev, outer._zones)
                            create_ptr = query.get('createPtrZone', ['false'])[0].lower() == 'true'
                            if ptr_zone_name:
                                ptr_rec = {
                                    "name": rev,
                                    "type": "PTR",
                                    "ttl": ttl,
                                    "rData": {"ptrName": domain},
                                    "comments": comments,
                                    "disabled": False,
                                }
                                outer._zones[ptr_zone_name]["records"].append(ptr_rec)
                            elif create_ptr:
                                # create /24 zone
                                suffix = _ptr_zone_suffix(rev)
                                if suffix and suffix not in outer._zones:
                                    outer._zones[suffix] = {
                                        "type": "Primary",
                                        "records": []
                                    }
                                    ptr_rec = {
                                        "name": rev,
                                        "type": "PTR",
                                        "ttl": ttl,
                                        "rData": {"ptrName": domain},
                                        "comments": comments,
                                        "disabled": False,
                                    }
                                    outer._zones[suffix]["records"].append(ptr_rec)
                    # response
                    zone_summary = outer._zone_summary(zone, zinfo)
                    outer._ok(self, {"zone": zone_summary, "addedRecord": rec})
                    return

                if path == "/api/zones/records/update":
                    if not outer._can_modify:
                        outer._error(self, "Access was denied to use Zones.Modify")
                        return
                    domain = query.get('domain', [''])[0]
                    zone = query.get('zone', [''])[0]
                    typ = query.get('type', [''])[0].upper()
                    znorm = _norm(zone)
                    with outer._lock:
                        zinfo = outer._zones.get(znorm)
                    if not zinfo:
                        outer._error(self, f"No such zone was found: {zone}")
                        return
                    if zinfo.get("type") == "Secondary":
                        outer._error(self, "Cannot update record: the zone is a Secondary zone and is read-only")
                        return
                    # find record
                    cur_ip = query.get('ipAddress', [''])[0] if typ in ('A', 'AAAA') else None
                    cur_ptr = query.get('ptrName', [''])[0] if typ == 'PTR' else None
                    with outer._lock:
                        rec_idx = None
                        for i, r in enumerate(zinfo.get("records", [])):
                            if _norm(r.get('name', '')) != _norm(domain) or r.get('type', '').upper() != typ:
                                continue
                            if typ in ('A', 'AAAA'):
                                if r.get('rData', {}).get('ipAddress') == cur_ip:
                                    rec_idx = i
                                    break
                            elif typ == 'PTR':
                                if r.get('rData', {}).get('ptrName') == cur_ptr:
                                    rec_idx = i
                                    break
                        if rec_idx is None:
                            outer._error(self, "Cannot update record: the record does not exist")
                            return
                        rec = zinfo["records"][rec_idx]
                    # apply changes
                    if 'ttl' in query:
                        try:
                            rec['ttl'] = int(query['ttl'][0])
                        except ValueError:
                            pass
                    if 'comments' in query:
                        rec['comments'] = query['comments'][0]
                    if typ in ('A', 'AAAA') and 'newIpAddress' in query:
                        new_ip = query['newIpAddress'][0]
                        rec['rData']['ipAddress'] = new_ip
                        # update PTR if needed
                        if query.get('ptr', ['false'])[0].lower() == 'true':
                            rev = _ptr_zone_from_ip(new_ip)
                            ptr_zone_name = _find_zone_for_ptr(rev, outer._zones)
                            create_ptr = query.get('createPtrZone', ['false'])[0].lower() == 'true'
                            with outer._lock:
                                if ptr_zone_name:
                                    # find existing PTR for this IP (old) and update? We'll just add/update.
                                    # For simplicity, we remove any PTR with same name (the reverse) and add new.
                                    zone_recs = outer._zones[ptr_zone_name]["records"]
                                    # remove old PTR for this domain? We'll just add new; duplicates okay for test.
                                    zone_recs.append({
                                        "name": rev,
                                        "type": "PTR",
                                        "ttl": rec.get('ttl', 3600),
                                        "rData": {"ptrName": domain},
                                        "comments": rec.get('comments', ""),
                                        "disabled": False,
                                    })
                                elif create_ptr:
                                    suffix = _ptr_zone_suffix(rev)
                                    if suffix and suffix not in outer._zones:
                                        outer._zones[suffix] = {"type": "Primary", "records": []}
                                    outer._zones[suffix]["records"].append({
                                        "name": rev,
                                        "type": "PTR",
                                        "ttl": rec.get('ttl', 3600),
                                        "rData": {"ptrName": domain},
                                        "comments": rec.get('comments', ""),
                                        "disabled": False,
                                    })
                    if typ == 'PTR' and 'newPtrName' in query:
                        rec['rData']['ptrName'] = query['newPtrName'][0]
                    outer._ok(self, {"zone": outer._zone_summary(zone, zinfo), "updatedRecord": rec})
                    return

                if path == "/api/zones/records/delete":
                    if not outer._can_delete:
                        outer._error(self, "Access was denied to use Zones.Delete")
                        return
                    domain = query.get('domain', [''])[0]
                    zone = query.get('zone', [''])[0]
                    typ = query.get('type', [''])[0].upper()
                    znorm = _norm(zone)
                    with outer._lock:
                        zinfo = outer._zones.get(znorm)
                    if not zinfo:
                        outer._error(self, f"No such zone was found: {zone}")
                        return
                    if zinfo.get("type") == "Secondary":
                        outer._error(self, "Cannot delete record: the zone is a Secondary zone and is read-only")
                        return
                    cur_ip = query.get('ipAddress', [''])[0] if typ in ('A', 'AAAA') else None
                    cur_ptr = query.get('ptrName', [''])[0] if typ == 'PTR' else None
                    with outer._lock:
                        del_idx = None
                        for i, r in enumerate(zinfo.get("records", [])):
                            if _norm(r.get('name', '')) != _norm(domain) or r.get('type', '').upper() != typ:
                                continue
                            if typ in ('A', 'AAAA'):
                                if r.get('rData', {}).get('ipAddress') == cur_ip:
                                    del_idx = i
                                    break
                            elif typ == 'PTR':
                                if r.get('rData', {}).get('ptrName') == cur_ptr:
                                    del_idx = i
                                    break
                            elif typ == 'CNAME':
                                del_idx = i
                                break
                        if del_idx is None:
                            outer._error(self, "Cannot delete record: the record does not exist")
                            return
                        del zinfo["records"][del_idx]
                    outer._ok(self, {})
                    return

                if path == "/api/admin/cluster/state":
                    if outer._cluster is None:
                        outer._ok(self, {"clusterInitialized": False})
                    else:
                        name = outer._cluster.get("name", "dns1.example.com")
                        ctype = outer._cluster.get("type", "Primary")
                        nodes = [
                            {
                                "id": 1,
                                "name": name,
                                "url": f"https://{name}:53443/",
                                "ipAddress": "127.0.0.1",
                                "type": ctype,
                                "state": "Self",
                            },
                            {
                                "id": 2,
                                "name": "dns2.example.com",
                                "url": "https://dns2.example.com:53443/",
                                "ipAddress": "127.0.0.2",
                                "type": "Secondary" if ctype == "Primary" else "Primary",
                                "state": "Connected",
                            },
                        ]
                        outer._ok(self, {
                            "clusterInitialized": True,
                            "dnsServerDomain": name,
                            "version": "14.0",
                            "clusterDomain": "example.com",
                            "clusterNodes": nodes,
                        })
                    return

                if path == "/api/zones/options/get":
                    zone = query.get('zone', [''])[0]
                    znorm = _norm(zone)
                    with outer._lock:
                        zinfo = outer._zones.get(znorm)
                    if not zinfo:
                        outer._error(self, f"No such zone was found: {zone}")
                        return
                    outer._ok(self, {
                        "name": zone,
                        "type": zinfo.get("type", "Primary"),
                        "disabled": False,
                        "update": "Deny",
                        "updateNetworkACL": [],
                        "updateSecurityPolicies": [],
                    })
                    return

                if path == "/api/user/session/get":
                    outer._ok(self, {
                        "username": "netlens",
                        "tokenName": "test",
                        "info": {"displayName": "Netlens", "username": "netlens"},
                    })
                    return

                # unknown path
                self.send_error(404)
                self.end_headers()

        return Handler

    # ------------------------------------------------------------------ public
    def start(self) -> str:
        handler = self._make_handler()
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        port = server.server_address[1]
        self._server = server
        self.url = f"http://127.0.0.1:{port}"
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            if self._thread:
                self._thread.join(timeout=5)
            self._server = None
            self._thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()

    def records(self, zone: str) -> List[Dict[str, Any]]:
        znorm = _norm(zone)
        with self._lock:
            zinfo = self._zones.get(znorm)
            if not zinfo:
                return []
            return list(zinfo.get("records", []))