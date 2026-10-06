from fastapi import APIRouter, Request

VERSION = "0.1.0"

router = APIRouter(prefix="/api", tags=["config"])


@router.get("/config")
async def get_config(request: Request) -> dict:
    settings = request.app.state.settings

    return {
        "version": VERSION,
        "ranges": list(settings.ranges),
        "quick_interval": settings.quick_interval,
        "deep_interval": settings.deep_interval,
        "terminal_enabled": settings.terminal_enabled,
        "snmp_enabled": settings.snmp_community is not None,
        "bind": f"{settings.bind_host}:{settings.bind_port}",
    }