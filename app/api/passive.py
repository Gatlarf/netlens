from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["passive"])


class PassiveBody(BaseModel):
    enabled: bool


def _control(request: Request):
    control = getattr(request.app.state, "passive", None)
    if control is None:
        raise HTTPException(status_code=404, detail="passive listening is not available here")
    return control


@router.get("/passive")
def get_passive(request: Request) -> dict:
    return _control(request).status()


@router.put("/passive")
async def put_passive(body: PassiveBody, request: Request) -> dict:
    control = _control(request)
    control.set_enabled(body.enabled)
    return control.status()
