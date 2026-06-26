from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.config import get_settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


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
    }
    if context:
        ctx.update(context)
    return templates.TemplateResponse(request, template_name, ctx)
