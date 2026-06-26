from dataclasses import dataclass, field
from enum import IntEnum


class AppRole(IntEnum):
    VIEWER = 1
    SCANNER = 2
    REMEDIATOR = 3
    ADMIN = 4


KEYCLOAK_ROLE_MAP: dict[str, AppRole] = {
    "vmstig-viewer": AppRole.VIEWER,
    "vmstig-scanner": AppRole.SCANNER,
    "vmstig-remediator": AppRole.REMEDIATOR,
    "vmstig-admin": AppRole.ADMIN,
}


ROLE_LABELS: dict[AppRole, str] = {
    AppRole.VIEWER: "Viewer",
    AppRole.SCANNER: "Scanner",
    AppRole.REMEDIATOR: "Remediator",
    AppRole.ADMIN: "Administrator",
}


def parse_keycloak_roles(claims: dict, client_id: str = "") -> list[AppRole]:
    names: set[str] = set()
    realm_roles = (claims.get("realm_access") or {}).get("roles") or []
    names.update(str(r) for r in realm_roles)

    resource_access = claims.get("resource_access") or {}
    if client_id and client_id in resource_access:
        names.update(str(r) for r in (resource_access[client_id].get("roles") or []))
    for client_roles in resource_access.values():
        if isinstance(client_roles, dict):
            names.update(str(r) for r in (client_roles.get("roles") or []))

    mapped = {KEYCLOAK_ROLE_MAP[name] for name in names if name in KEYCLOAK_ROLE_MAP}
    return sorted(mapped, key=lambda role: role.value)


@dataclass
class AuthenticatedUser:
    sub: str
    username: str
    email: str = ""
    display_name: str = ""
    roles: list[AppRole] = field(default_factory=list)

    @property
    def effective_role(self) -> AppRole:
        if not self.roles:
            return AppRole.VIEWER
        return max(self.roles, key=lambda role: role.value)

    @property
    def role_label(self) -> str:
        return ROLE_LABELS.get(self.effective_role, "Viewer")

    def satisfies(self, minimum: AppRole) -> bool:
        return self.effective_role.value >= minimum.value

    def can_view(self) -> bool:
        return self.satisfies(AppRole.VIEWER)

    def can_scan(self) -> bool:
        return self.satisfies(AppRole.SCANNER)

    def can_remediate(self) -> bool:
        return self.satisfies(AppRole.REMEDIATOR)

    def can_admin(self) -> bool:
        return self.satisfies(AppRole.ADMIN)
