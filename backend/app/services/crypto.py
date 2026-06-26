import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.services.credential_key import resolve_credential_encryption_key


def _fernet() -> Fernet:
    key = resolve_credential_encryption_key()[0].encode()
    if len(key) == 44 and key.decode().endswith("="):
        return Fernet(key)
    digest = hashlib.sha256(key).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ValueError(
            "Unable to decrypt stored credential. The scan worker may be using a different "
            "encryption key than when this vCenter was saved. Ensure web and worker share "
            "CREDENTIAL_ENCRYPTION_KEY (or the same /data/secrets volume), then re-save the "
            "vCenter password."
        ) from exc
