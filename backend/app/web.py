from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.config import get_settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
STATIC_DIR = Path(__file__).parent / "static"
TOUR_STATIC_FILES = (
    "tour-guide-1.png",
    "tour-guide-2.png",
    "tour-guide-3.png",
    "tour-guide-4.png",
    "tour-guide.js",
    "tour-guide.css",
)


def tour_static_context() -> dict:
    versions: dict[str, str] = {}
    for name in TOUR_STATIC_FILES:
        path = STATIC_DIR / name
        if path.is_file():
            versions[name] = str(int(path.stat().st_mtime))
    latest = max(versions.values(), default="0")
    return {"tour_asset_versions": versions, "tour_static_version": latest}


def url_for_path(path: str, root_path: str | None = None) -> str:
    root = (root_path if root_path is not None else get_settings().app_root_path or "").rstrip("/")
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{root}{path}" if root else path


SCANS_PER_PAGE_OPTIONS = ("20", "50", "100", "all")
DEFAULT_SCANS_PER_PAGE = "20"


def scans_list_url(
    page: int = 1,
    per_page: str = DEFAULT_SCANS_PER_PAGE,
    root_path: str | None = None,
) -> str:
    base = url_for_path("/scans", root_path)
    params: list[str] = []
    if per_page != DEFAULT_SCANS_PER_PAGE:
        params.append(f"per_page={per_page}")
    if page > 1:
        params.append(f"page={page}")
    if not params:
        return base
    return f"{base}?{'&'.join(params)}"


def render(request: Request, template_name: str, context: dict | None = None):
    settings = get_settings()
    root_path = settings.app_root_path or ""
    user = getattr(request.state, "user", None)
    ctx = {
        "root_path": root_path,
        "url": lambda p: url_for_path(p, root_path),
        "current_user": user,
        "oidc_enabled": settings.oidc_enabled,
        **tour_static_context(),
    }
    if context:
        ctx.update(context)
    return templates.TemplateResponse(request, template_name, ctx)
