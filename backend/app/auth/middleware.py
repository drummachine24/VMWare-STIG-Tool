from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from app.auth.oidc import app_url, login_redirect_url, user_from_session
from app.auth.roles import AuthenticatedUser, AppRole
from app.config import get_settings


def _dev_user() -> AuthenticatedUser:
    return AuthenticatedUser(
        sub="dev-local",
        username="dev-local",
        display_name="Local Dev User",
        roles=[AppRole.ADMIN],
    )


class AuthMiddleware(BaseHTTPMiddleware):
    PUBLIC_EXACT = {
        "/health",
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
        "/auth/no-roles",
    }
    PUBLIC_PREFIXES = ("/static",)

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path

        if not settings.oidc_enabled:
            request.state.user = _dev_user()
            return await call_next(request)

        root = (settings.app_root_path or "").rstrip("/")
        if root and path.startswith(root):
            path = path[len(root) :] or "/"

        if path in self.PUBLIC_EXACT or any(
            path.startswith(prefix) for prefix in self.PUBLIC_PREFIXES
        ):
            return await call_next(request)

        user = user_from_session(request.session)
        if not user:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Not authenticated"}, status_code=401)
            next_path = request.url.path
            if request.url.query:
                next_path = f"{next_path}?{request.url.query}"
            return RedirectResponse(login_redirect_url(settings, next_path), status_code=302)

        request.state.user = user
        if not user.roles and not path.startswith("/api/auth"):
            if path.startswith("/api/"):
                return JSONResponse(
                    {"detail": "No VMware STIG Tool roles assigned in Keycloak"},
                    status_code=403,
                )
            return RedirectResponse(app_url(settings, "/auth/no-roles"), status_code=302)

        return await call_next(request)
