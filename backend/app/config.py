from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_secret_key: str = "change-me"
    app_secret_key_file: str = "/data/secrets/app_secret_key"
    credential_encryption_key: str = "change-me-use-fernet-key"
    credential_encryption_key_file: str = "/data/secrets/credential_encryption_key"

    database_url: str = "postgresql://stig:stig@localhost:5432/stigtool"
    redis_url: str = "redis://localhost:6379/0"

    stig_profiles_path: str = "/usr/share/stigs"
    reports_path: str = "/data/reports"

    vcf_profile_base: str = "vcf/9.x/Y25M06-srg"
    vcf_baseline_profile: str = "inspec/vmware-cloud-foundation-stig-baseline/vsphere"
    vcf_vcsa_profile: str = "inspec/vmware-cloud-foundation-vcsa-stig-baseline"
    vcf_metadata: str = (
        "inspec/vmware-cloud-foundation-stig-baseline/saf_cli_hdf2ckl_metadata.json"
    )

    dry_run: bool = False
    scan_timeout_seconds: int = 7200
    ckl_export_allowed_roots: str = "/data/reports,/data/ckl-exports"
    # Comma-separated ESXi NTP servers injected for VCFE-9X-000121 remediation
    remediation_esxi_ntp_servers: str = "time-a-g.nist.gov,time-b-g.nist.gov"

    # Public URL and reverse-proxy subpath (e.g. /vmstigtool behind nginx)
    app_root_path: str = ""
    app_public_url: str = ""

    # OIDC / Keycloak
    oidc_enabled: bool = False
    oidc_issuer_url: str = ""
    oidc_metadata_url: str = ""
    oidc_token_url: str = ""
    oidc_userinfo_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_ssl_verify: bool = True
    # Path to a PEM bundle of DoD/public CAs inside the container (for JWKS HTTPS validation)
    oidc_ca_bundle: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
