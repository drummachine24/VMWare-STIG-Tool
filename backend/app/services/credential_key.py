import logging
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)
INSECURE_CREDENTIAL_KEY_DEFAULTS = frozenset({"", "change-me-use-fernet-key"})


def is_env_credential_key_configured(value: str) -> bool:
    return bool(value and value not in INSECURE_CREDENTIAL_KEY_DEFAULTS)


def credential_key_file_path(settings: Settings | None = None) -> Path:
    cfg = settings or get_settings()
    return Path(cfg.credential_encryption_key_file)


def read_stored_credential_key(settings: Settings | None = None) -> str | None:
    path = credential_key_file_path(settings)
    if not path.is_file():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def write_stored_credential_key(key: str, settings: Settings | None = None) -> Path:
    path = credential_key_file_path(settings)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(key, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        logger.warning("Could not write credential encryption key to %s: %s", path, exc)
        raise
    return path


def generate_credential_key() -> str:
    return Fernet.generate_key().decode()


def resolve_credential_encryption_key(settings: Settings | None = None) -> tuple[str, str]:
    cfg = settings or get_settings()
    if is_env_credential_key_configured(cfg.credential_encryption_key):
        return cfg.credential_encryption_key, "environment"

    stored = read_stored_credential_key(cfg)
    if stored:
        return stored, "file"

    return cfg.credential_encryption_key, "default"


def credential_key_status(settings: Settings | None = None) -> dict:
    cfg = settings or get_settings()
    key, source = resolve_credential_encryption_key(cfg)
    insecure = source == "default" or key in INSECURE_CREDENTIAL_KEY_DEFAULTS
    path = credential_key_file_path(cfg)
    return {
        "source": source,
        "insecure": insecure,
        "env_locked": is_env_credential_key_configured(cfg.credential_encryption_key),
        "file_path": str(path),
        "file_exists": path.is_file(),
        "preview": f"…{key[-4:]}" if key and not insecure else None,
    }


def ensure_credential_encryption_key(settings: Settings | None = None) -> bool:
    """Create a stored Fernet key on first boot when no secure key is configured."""
    cfg = settings or get_settings()
    if is_env_credential_key_configured(cfg.credential_encryption_key):
        return False
    if read_stored_credential_key(cfg):
        return False
    try:
        write_stored_credential_key(generate_credential_key(), cfg)
    except OSError:
        return False
    return True


def sync_credential_key_file_from_env(settings: Settings | None = None) -> bool:
    """Mirror CREDENTIAL_ENCRYPTION_KEY from the environment into the shared secrets file."""
    cfg = settings or get_settings()
    if not is_env_credential_key_configured(cfg.credential_encryption_key):
        return False
    if read_stored_credential_key(cfg) == cfg.credential_encryption_key:
        return False
    try:
        write_stored_credential_key(cfg.credential_encryption_key, cfg)
        return True
    except OSError:
        return False
