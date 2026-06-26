import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth.dependencies import get_current_user, require_admin
from app.auth.oidc import app_url, claims_from_oidc_token, get_oauth, user_from_claims
from app.auth.roles import KEYCLOAK_ROLE_MAP, AuthenticatedUser
from app.config import get_settings
from app.services.app_secret import app_secret_status, create_app_secret_key
from app.services.credential_key import credential_key_status
from app.web import render, url_for_path

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


@router.get("/auth/login")
async def auth_login(request: Request, next: str = "/"):
    settings = get_settings()
    if not settings.oidc_enabled:
        return RedirectResponse(app_url(settings, next or "/"))

    oauth = get_oauth(settings)
    client = oauth.create_client("keycloak")
    if client is None:
        logger.error("OIDC client 'keycloak' is not registered; check OIDC_METADATA_URL")
        raise HTTPException(status_code=503, detail="OIDC is not configured correctly")

    redirect_uri = settings.oidc_redirect_uri or app_url(settings, "/auth/callback")
    request.session["auth_next"] = next or "/"
    try:
        return await client.authorize_redirect(request, redirect_uri)
    except Exception as exc:
        logger.exception("OIDC authorize redirect failed")
        raise HTTPException(
            status_code=503,
            detail=(
                "Could not start Keycloak login. The web container may be unable to reach "
                "OIDC metadata — set OIDC_METADATA_URL to an internal Keycloak URL. "
                f"Error: {exc}"
            ),
        ) from exc


@router.get("/auth/callback")
async def auth_callback(request: Request):
    settings = get_settings()
    if not settings.oidc_enabled:
        return RedirectResponse(app_url(settings, "/"))

    oauth = get_oauth(settings)
    client = oauth.create_client("keycloak")
    if client is None:
        raise HTTPException(status_code=503, detail="OIDC is not configured correctly")
    try:
        token = await client.authorize_access_token(request)
    except Exception as exc:
        logger.exception("OIDC callback failed")
        raise HTTPException(status_code=400, detail=f"OIDC login failed: {exc}") from exc

    claims = claims_from_oidc_token(token)
    request.session["access_token"] = token.get("access_token")
    request.session["user"] = claims
    user = user_from_claims(claims, settings)
    if not user.roles:
        return RedirectResponse(app_url(settings, "/auth/no-roles"), status_code=302)

    next_path = request.session.pop("auth_next", "/") or "/"
    return RedirectResponse(app_url(settings, next_path), status_code=302)


@router.get("/auth/logout")
async def auth_logout(request: Request):
    settings = get_settings()
    request.session.clear()
    if settings.oidc_enabled and settings.oidc_issuer_url:
        params = {
            "client_id": settings.oidc_client_id,
            "post_logout_redirect_uri": app_url(settings, "/"),
        }
        logout_url = (
            f"{settings.oidc_issuer_url.rstrip('/')}/protocol/openid-connect/logout"
        )
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return RedirectResponse(f"{logout_url}?{query}", status_code=302)
    return RedirectResponse(app_url(settings, "/"), status_code=302)


@router.get("/auth/no-roles", response_class=HTMLResponse)
async def auth_no_roles(request: Request):
    settings = get_settings()
    return render(
        request,
        "auth_no_roles.html",
        {
            "keycloak_roles": sorted(KEYCLOAK_ROLE_MAP.keys()),
            "logout_url": app_url(settings, "/auth/logout"),
        },
    )


@router.get("/auth/me")
def auth_me(user: AuthenticatedUser = Depends(get_current_user)):
    return {
        "sub": user.sub,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "roles": [role.name.lower() for role in user.roles],
        "effective_role": user.effective_role.name.lower(),
    }


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(
    request: Request,
    user: AuthenticatedUser = Depends(require_admin),
):
    settings = get_settings()
    flash_secret = request.session.pop("flash_app_secret", None)
    return render(
        request,
        "admin.html",
        {
            "user": user,
            "settings": settings,
            "keycloak_roles": sorted(KEYCLOAK_ROLE_MAP.keys()),
            "login_url": app_url(settings, "/auth/login"),
            "logout_url": app_url(settings, "/auth/logout"),
            "callback_url": settings.oidc_redirect_uri or app_url(settings, "/auth/callback"),
            "post_logout_url": app_url(settings, "/"),
            "app_secret": app_secret_status(settings),
            "credential_key": credential_key_status(settings),
            "flash_app_secret": flash_secret,
        },
    )


@router.post("/admin/app-secret/generate")
async def admin_generate_app_secret(
    request: Request,
    _user: AuthenticatedUser = Depends(require_admin),
    regenerate: str = Form(""),
):
    settings = get_settings()
    try:
        key = create_app_secret_key(settings, force=regenerate == "true")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    request.session["flash_app_secret"] = key
    return RedirectResponse(url_for_path("/admin"), status_code=303)
