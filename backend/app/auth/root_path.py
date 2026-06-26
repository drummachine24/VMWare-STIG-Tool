from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import get_settings


class RootPathStripMiddleware(BaseHTTPMiddleware):
    """Strip APP_ROOT_PATH from incoming paths when nginx forwards the full URI."""

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        root = (settings.app_root_path or "").rstrip("/")
        path = request.scope.get("path") or request.url.path
        if root and path.startswith(root + "/"):
            request.scope["path"] = path[len(root) :] or "/"
        elif root and path == root:
            request.scope["path"] = "/"
        return await call_next(request)
