Create app/api/scans.py (FastAPI). Imports: from app.api.devices import get_conn; from app.scanner.scans import list_scans, running_scan (list_scans(conn, limit=50) -> list[dict] newest first; running_scan(conn) -> dict | None).
router = APIRouter(prefix="/api", tags=["scans"]).
- GET /scans?limit=50 (limit 1-200, else 422): returns list_scans(conn, limit).
- GET /scans/current: returns {"running": bool, "scan": dict | None} using running_scan.
