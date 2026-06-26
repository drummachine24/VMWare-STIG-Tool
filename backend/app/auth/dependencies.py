from fastapi import Depends, HTTPException, Request, status

from app.auth.roles import AppRole, AuthenticatedUser
from app.config import get_settings


def _dev_user() -> AuthenticatedUser:
    return AuthenticatedUser(
        sub="dev-local",
        username="dev-local",
        display_name="Local Dev User",
        roles=[AppRole.ADMIN],
    )


def get_current_user(request: Request) -> AuthenticatedUser:
    settings = get_settings()
    if not settings.oidc_enabled:
        return _dev_user()

    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def require_minimum_role(minimum: AppRole):
    def dependency(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not user.satisfies(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum.name.lower()} role or higher",
            )
        return user

    return dependency


require_viewer = require_minimum_role(AppRole.VIEWER)
require_scanner = require_minimum_role(AppRole.SCANNER)
require_remediator = require_minimum_role(AppRole.REMEDIATOR)
require_admin = require_minimum_role(AppRole.ADMIN)
