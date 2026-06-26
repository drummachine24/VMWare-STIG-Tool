import base64
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth

from app.auth.roles import AuthenticatedUser, parse_keycloak_roles
from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

_oauth: OAuth | None = None
_combined_ca_bundle_path: str | None = None


def _strip_pem_certs(raw: str) -> str:
    blocks: list[str] = []
    cert_lines: list[str] = []
    in_cert = False
    for line in raw.splitlines():
        if "BEGIN CERTIFICATE" in line:
            in_cert = True
            cert_lines = [line]
            continue
        if in_cert:
            cert_lines.append(line)
            if "END CERTIFICATE" in line:
                blocks.append("\n".join(cert_lines))
                in_cert = False
    return "\n".join(blocks) + ("\n" if blocks else "")


def prepare_oidc_ca_bundle(cfg: Settings) -> str:
    """Build a clean PEM bundle for httpx/authlib (certifi + optional DoD/org CAs)."""
    global _combined_ca_bundle_path
    if _combined_ca_bundle_path:
        return _combined_ca_bundle_path

    parts: list[str] = []
    try:
        import certifi

        parts.append(_strip_pem_certs(Path(certifi.where()).read_text(encoding="utf-8")))
    except Exception as exc:
        logger.warning("Could not load certifi CA bundle: %s", exc)

    if cfg.oidc_ca_bundle:
        src = Path(cfg.oidc_ca_bundle)
        if not src.is_file():
            logger.error("OIDC_CA_BUNDLE file not found: %s", src)
        else:
            parts.append(_strip_pem_certs(src.read_text(encoding="utf-8")))

    combined = "\n".join(p for p in parts if p.strip())
    if not combined.strip():
        _combined_ca_bundle_path = ""
        return _combined_ca_bundle_path

    dest = Path("/data/secrets/oidc-ca-bundle.pem")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(combined, encoding="utf-8")
    try:
        dest.chmod(0o644)
    except OSError:
        pass
    _combined_ca_bundle_path = str(dest)
    logger.info("OIDC CA bundle prepared at %s", dest)
    return _combined_ca_bundle_path


def oidc_http_verify(cfg: Settings) -> bool | str:
    if not cfg.oidc_ssl_verify:
        return False
    if cfg.oidc_ca_bundle:
        prepared = prepare_oidc_ca_bundle(cfg)
        if prepared:
            return prepared
    return True

def get_oauth(settings: Settings | None = None) -> OAuth:
    global _oauth
    cfg = settings or get_settings()
    if _oauth is None:
        _oauth = OAuth()
    if not cfg.oidc_enabled:
        return _oauth

    metadata_url = cfg.oidc_metadata_url
    if not metadata_url and cfg.oidc_issuer_url:
        metadata_url = f"{cfg.oidc_issuer_url.rstrip('/')}/.well-known/openid-configuration"

    if metadata_url and _oauth.create_client("keycloak") is None:
        verify = oidc_http_verify(cfg)
        register_kwargs: dict[str, Any] = {
            "name": "keycloak",
            "client_id": cfg.oidc_client_id,
            "client_secret": cfg.oidc_client_secret,
            "server_metadata_url": metadata_url,
            "client_kwargs": {"scope": cfg.oidc_scopes, "verify": verify},
            "verify": verify,
        }
        if cfg.oidc_issuer_url:
            issuer = cfg.oidc_issuer_url.rstrip("/")
            register_kwargs["authorize_url"] = f"{issuer}/protocol/openid-connect/auth"
        if cfg.oidc_token_url:
            register_kwargs["access_token_url"] = cfg.oidc_token_url
        if cfg.oidc_userinfo_url:
            register_kwargs["userinfo_endpoint"] = cfg.oidc_userinfo_url
        logger.info("Registering OIDC client (verify=%s)", verify)
        _oauth.register(**register_kwargs)
    return _oauth


async def check_oidc_discovery(settings: Settings | None = None) -> dict[str, Any]:
    cfg = settings or get_settings()
    metadata_url = cfg.oidc_metadata_url
    if not metadata_url and cfg.oidc_issuer_url:
        metadata_url = f"{cfg.oidc_issuer_url.rstrip('/')}/.well-known/openid-configuration"
    if not metadata_url:
        return {"ok": False, "error": "No OIDC metadata URL configured"}

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=oidc_http_verify(cfg)) as client:
            resp = await client.get(metadata_url)
            resp.raise_for_status()
            data = resp.json()
            return {
                "ok": True,
                "metadata_url": metadata_url,
                "issuer": data.get("issuer"),
                "authorization_endpoint": data.get("authorization_endpoint"),
                "token_endpoint": data.get("token_endpoint"),
            }
    except Exception as exc:
        logger.exception("OIDC metadata discovery failed for %s", metadata_url)
        return {"ok": False, "metadata_url": metadata_url, "error": str(exc)}


def app_url(settings: Settings | None = None, path: str = "/") -> str:
    cfg = settings or get_settings()
    base = (cfg.app_public_url or "").rstrip("/")
    root = (cfg.app_root_path or "").rstrip("/")
    suffix = path if path.startswith("/") else f"/{path}"

    if root and base.endswith(root):
        return f"{base}{suffix}"

    if root and not suffix.startswith(root + "/") and suffix != root:
        suffix = f"{root}{suffix}"
    return f"{base}{suffix}" if base else suffix


def login_redirect_url(settings: Settings | None = None, next_path: str = "/") -> str:
    cfg = settings or get_settings()
    params = urlencode({"next": next_path})
    return f"{app_url(cfg, '/auth/login')}?{params}"


def _decode_jwt_payload(jwt_token: str) -> dict[str, Any]:
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def claims_from_oidc_token(token: dict[str, Any]) -> dict[str, Any]:
    """Merge userinfo, ID token, and access token claims (roles live in access token)."""
    userinfo = token.get("userinfo") if isinstance(token.get("userinfo"), dict) else {}
    id_token = token.get("id_token") if isinstance(token.get("id_token"), dict) else {}
    access_claims: dict[str, Any] = {}
    access = token.get("access_token")
    if isinstance(access, str):
        access_claims = _decode_jwt_payload(access)

    # Access token last so realm_access / resource_access from Keycloak win.
    claims = {**userinfo, **id_token, **access_claims}
    if claims:
        realm_roles = (claims.get("realm_access") or {}).get("roles") or []
        logger.debug("OIDC mapped role candidates from token: %s", realm_roles)
        return claims

    skip = {"access_token", "refresh_token", "token_type", "expires_in", "id_token", "userinfo"}
    return {k: v for k, v in token.items() if k not in skip}


def user_from_claims(claims: dict[str, Any], settings: Settings | None = None) -> AuthenticatedUser:
    cfg = settings or get_settings()
    username = (
        claims.get("preferred_username")
        or claims.get("username")
        or claims.get("email")
        or claims.get("sub")
        or "unknown"
    )
    display = claims.get("name") or username
    roles = parse_keycloak_roles(claims, cfg.oidc_client_id)
    if not roles:
        realm_roles = (claims.get("realm_access") or {}).get("roles") or []
        logger.warning(
            "User %s authenticated but no vmstig-* roles were mapped (token realm roles: %s)",
            username,
            realm_roles,
        )
    return AuthenticatedUser(
        sub=str(claims.get("sub") or username),
        username=str(username),
        email=str(claims.get("email") or ""),
        display_name=str(display),
        roles=roles,
    )


def user_from_session(session: dict, settings: Settings | None = None) -> AuthenticatedUser | None:
    claims = session.get("user")
    if not isinstance(claims, dict):
        return None
    return user_from_claims(claims, settings)


async def refresh_user_claims(session: dict, settings: Settings | None = None) -> AuthenticatedUser | None:
    cfg = settings or get_settings()
    access_token = session.get("access_token")
    if not access_token or not cfg.oidc_userinfo_url:
        return user_from_session(session, cfg)

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=oidc_http_verify(cfg)) as client:
            resp = await client.get(
                cfg.oidc_userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            claims = resp.json()
            session["user"] = claims
            return user_from_claims(claims, cfg)
    except Exception as exc:
        logger.warning("Could not refresh OIDC userinfo: %s", exc)
        return user_from_session(session, cfg)
