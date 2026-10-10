"""The changelog (CHANGELOG.md) for the "What's new" popup and Settings → About."""

from fastapi import APIRouter

from app import changelog
from app.version import VERSION

router = APIRouter(prefix="/api", tags=["changelog"])


@router.get("/changelog")
def get_changelog(since: str | None = None) -> dict:
    """All releases, newest first; with `since` only those after that version (up to the running one)."""
    releases = changelog.load()
    if since:
        releases = changelog.releases_between(releases, since, VERSION)
    return {"current": VERSION, "releases": releases}
