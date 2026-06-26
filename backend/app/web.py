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
