from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.models import Base

settings = get_settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

_SCAN_JOB_COLUMNS = [
    ("cancel_requested", "BOOLEAN DEFAULT FALSE"),
    ("progress_message", "TEXT"),
    ("progress_current", "INTEGER DEFAULT 0"),
    ("progress_total", "INTEGER DEFAULT 0"),
    ("selected_targets_json", "TEXT"),
    ("schedule_id", "INTEGER"),
    ("ckl_export_path", "VARCHAR(512)"),
    ("ckl_export_dir", "VARCHAR(512)"),
]

_SCAN_SCHEDULE_COLUMNS = [
    ("ckl_export_path", "VARCHAR(512)"),
]

_SCAN_RESULT_COLUMNS = [
    ("count_nf", "INTEGER"),
    ("count_nr", "INTEGER"),
    ("count_na", "INTEGER"),
    ("count_open", "INTEGER"),
]


def _migrate_scan_jobs() -> None:
    with engine.begin() as conn:
        for name, col_type in _SCAN_JOB_COLUMNS:
            conn.execute(
                text(f"ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS {name} {col_type}")
            )


def _migrate_scan_results() -> None:
    with engine.begin() as conn:
        for name, col_type in _SCAN_RESULT_COLUMNS:
            conn.execute(
                text(f"ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS {name} {col_type}")
            )


_REMEDIATION_JOB_COLUMNS = [
    ("progress_message", "TEXT"),
    ("progress_current", "INTEGER DEFAULT 0"),
    ("progress_total", "INTEGER DEFAULT 0"),
    ("variables_content", "TEXT"),
]


def _migrate_remediation_jobs() -> None:
    with engine.begin() as conn:
        for name, col_type in _REMEDIATION_JOB_COLUMNS:
            conn.execute(
                text(
                    f"ALTER TABLE remediation_jobs ADD COLUMN IF NOT EXISTS {name} {col_type}"
                )
            )


def _migrate_scan_schedules() -> None:
    with engine.begin() as conn:
        for name, col_type in _SCAN_SCHEDULE_COLUMNS:
            conn.execute(
                text(
                    f"ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS {name} {col_type}"
                )
            )


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    try:
        _migrate_scan_jobs()
        _migrate_scan_results()
        _migrate_remediation_jobs()
        _migrate_scan_schedules()
    except Exception:
        pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
