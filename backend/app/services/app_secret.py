import logging
import secrets
from pathlib import Path

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)
INSECURE_APP_SECRET_DEFAULTS = frozenset(
    {"", "change-me", "change-me-to-a-random-32-byte-key"}
)


def is_env_app_secret_configured(value: str) -> bool:
    return bool(value and value not in INSECURE_APP_SECRET_DEFAULTS)


def app_secret_file_path(settings: Settings | None = None) -> Path:
    cfg = settings or get_settings()
    return Path(cfg.app_secret_key_file)


def read_stored_app_secret(settings: Settings | None = None) -> str | None:
    path = app_secret_file_path(settings)
    if not path.is_file():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def write_stored_app_secret(key: str, settings: Settings | None = None) -> Path:
    path = app_secret_file_path(settings)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(key, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        logger.warning("Could not write app secret key to %s: %s", path, exc)
        raise
    return path

def generate_app_secret() -> str:
    return secrets.token_urlsafe(32)


def resolve_app_secret_key(settings: Settings | None = None) -> tuple[str, str]:
    cfg = settings or get_settings()
    if is_env_app_secret_configured(cfg.app_secret_key):
        return cfg.app_secret_key, "environment"

    stored = read_stored_app_secret(cfg)
    if stored:
        return stored, "file"

    return cfg.app_secret_key, "default"


def app_secret_status(settings: Settings | None = None) -> dict:
    cfg = settings or get_settings()
    key, source = resolve_app_secret_key(cfg)
    insecure = source == "default" or key in INSECURE_APP_SECRET_DEFAULTS
    path = app_secret_file_path(cfg)
    return {
        "source": source,
        "insecure": insecure,
        "env_locked": is_env_app_secret_configured(cfg.app_secret_key),
        "file_path": str(path),
        "file_exists": path.is_file(),
        "preview": f"…{key[-4:]}" if key and not insecure else None,
    }


def ensure_app_secret_key(settings: Settings | None = None) -> bool:
    """Create a stored secret on first boot when no secure key is configured."""
    cfg = settings or get_settings()
    if is_env_app_secret_configured(cfg.app_secret_key):
        return False
    if read_stored_app_secret(cfg):
        return False
    try:
        write_stored_app_secret(generate_app_secret(), cfg)
    except OSError:
        return False
    return True

def create_app_secret_key(settings: Settings | None = None, *, force: bool = False) -> str:
    cfg = settings or get_settings()
    if is_env_app_secret_configured(cfg.app_secret_key):
        raise ValueError("APP_SECRET_KEY is set via environment and cannot be replaced in the app.")

    if not force and read_stored_app_secret(cfg):
        raise ValueError("An app secret key file already exists. Use regenerate to replace it.")

    key = generate_app_secret()
    write_stored_app_secret(key, cfg)
    get_settings.cache_clear()
    return key
