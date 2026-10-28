"""The software bill of materials of this installation (administrators): CycloneDX 1.5 by default, SPDX 2.3 with ?format=spdx. See app/sbom.py."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app import sbom
from app.auth import require_admin

router = APIRouter(prefix="/api", tags=["sbom"])


@router.get("/sbom")
def get_sbom(request: Request, format: str = "cyclonedx") -> JSONResponse:
    require_admin(request)
    if format not in ("cyclonedx", "cdx", "spdx"):
        raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")
    doc = sbom.render(format)
    kind = "spdx" if format == "spdx" else "cdx"
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="netlens-{doc.get("version", "")}-{kind}.json"'.replace("netlens--", "netlens-"),
                                      "Cache-Control": "no-store"})
