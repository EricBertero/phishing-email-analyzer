"""SQLite persistence: scan results, the mailbox change cursor and the intel cache.

Only metadata and findings are stored, never message bodies or attachments.
Datetimes are timezone-aware UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Column, UniqueConstraint, inspect, text
from sqlmodel import Field, Session, SQLModel, create_engine, select

from phishanalyzer.models import Email, Level, Verdict


def utcnow() -> datetime:
    return datetime.now(UTC)


def _to_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:  # e.g. "Date: ... -0000" means "UTC, origin unknown"
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class ScannedEmail(SQLModel, table=True):
    __tablename__ = "scanned_emails"
    __table_args__ = (UniqueConstraint("provider", "provider_id"),)

    id: int | None = Field(default=None, primary_key=True)
    provider: str = Field(index=True)
    provider_id: str
    message_id: str | None = None
    subject: str = ""
    from_addr: str | None = None
    from_display: str | None = None
    sender_ip: str | None = None
    sent_at: datetime | None = None
    scanned_at: datetime = Field(default_factory=utcnow, index=True)
    score: int | None = None
    level: Level | None = Field(default=None, index=True)
    partial: bool = False
    findings: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    labeled: bool = False
    error: str | None = None
    # Times a partial verdict (some intel lookups unavailable) has been re-analysed.
    rechecks: int = 0


class PollState(SQLModel, table=True):
    __tablename__ = "poll_state"

    provider: str = Field(primary_key=True)
    cursor: str
    updated_at: datetime = Field(default_factory=utcnow)


class IntelCacheEntry(SQLModel, table=True):
    __tablename__ = "intel_cache"

    key: str = Field(primary_key=True)
    value: Any = Field(sa_column=Column(JSON))
    expires_at: datetime = Field(index=True)


class SqlIntelCache:
    """Persistent cache for threat-intel lookups, so restarts don't burn API quota."""

    def __init__(self, engine):
        self.engine = engine

    def get(self, key: str) -> Any | None:
        with Session(self.engine) as s:
            entry = s.get(IntelCacheEntry, key)
            if entry is None or entry.expires_at < utcnow():
                return None
            return entry.value

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        with Session(self.engine) as s:
            entry = s.get(IntelCacheEntry, key) or IntelCacheEntry(
                key=key, value=value, expires_at=utcnow()
            )
            entry.value = value
            entry.expires_at = utcnow() + timedelta(seconds=ttl_seconds)
            s.add(entry)
            s.commit()


def _add_missing_columns(engine) -> None:
    """Minimal forward migration: add columns introduced after a DB was created.

    Only nullable/defaulted columns are ever added, which SQLite supports in place.
    """
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in SQLModel.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                ddl = column.type.compile(dialect=engine.dialect)
                default = column.default.arg if column.default is not None else None
                if isinstance(default, bool):
                    default = int(default)
                clause = f" DEFAULT {default!r}" if isinstance(default, int | str) else ""
                conn.execute(
                    text(f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {ddl}{clause}')
                )


class Store:
    def __init__(self, db_path: Path | str):
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{db_path}")
        SQLModel.metadata.create_all(self.engine)
        _add_missing_columns(self.engine)

    def intel_cache(self) -> SqlIntelCache:
        return SqlIntelCache(self.engine)

    # --- cursor -------------------------------------------------------------------------
    def get_cursor(self, provider: str) -> str | None:
        with Session(self.engine) as s:
            state = s.get(PollState, provider)
            return state.cursor if state else None

    def set_cursor(self, provider: str, cursor: str) -> None:
        with Session(self.engine) as s:
            state = s.get(PollState, provider) or PollState(provider=provider, cursor=cursor)
            state.cursor, state.updated_at = cursor, utcnow()
            s.add(state)
            s.commit()

    # --- results ------------------------------------------------------------------------
    def is_scanned(self, provider: str, provider_id: str) -> bool:
        with Session(self.engine) as s:
            return s.exec(self._by_id(provider, provider_id)).first() is not None

    def save_result(
        self, provider: str, email: Email, verdict: Verdict, rechecks: int = 0
    ) -> ScannedEmail:
        row = ScannedEmail(
            provider=provider,
            provider_id=email.provider_id or "",
            message_id=email.message_id,
            subject=email.subject,
            from_addr=email.from_addr,
            from_display=email.from_display,
            sender_ip=email.sender_ip,
            sent_at=_to_utc(email.date),
            score=verdict.score,
            level=verdict.level,
            partial=verdict.partial,
            findings=[f.model_dump(mode="json") for f in verdict.findings],
            rechecks=rechecks,
        )
        return self._upsert(row)

    def save_error(self, provider: str, provider_id: str, error: str) -> ScannedEmail:
        return self._upsert(ScannedEmail(provider=provider, provider_id=provider_id, error=error))

    def mark_labeled(self, row_id: int) -> None:
        with Session(self.engine) as s:
            row = s.get(ScannedEmail, row_id)
            if row:
                row.labeled = True
                s.add(row)
                s.commit()

    def stop_rechecks(self, row_id: int | None) -> None:
        with Session(self.engine) as s:
            row = s.get(ScannedEmail, row_id)
            if row:
                row.rechecks = 1_000
                s.add(row)
                s.commit()

    def unlabeled(self, provider: str, limit: int = 100) -> list[ScannedEmail]:
        with Session(self.engine) as s:
            query = (
                select(ScannedEmail)
                .where(ScannedEmail.provider == provider)
                .where(ScannedEmail.labeled == False)  # noqa: E712 (SQL expression)
                .where(ScannedEmail.level != None)  # noqa: E711
                .order_by(ScannedEmail.id)
                .limit(limit)
            )
            return list(s.exec(query))

    def due_for_recheck(
        self,
        provider: str,
        max_rechecks: int = 3,
        min_age: timedelta = timedelta(minutes=10),
        max_age: timedelta = timedelta(days=2),
        limit: int = 20,
    ) -> list[ScannedEmail]:
        """Partial verdicts old enough to retry the lookups that were unavailable."""
        now = utcnow()
        with Session(self.engine) as s:
            query = (
                select(ScannedEmail)
                .where(ScannedEmail.provider == provider)
                .where(ScannedEmail.partial == True)  # noqa: E712 (SQL expression)
                .where(ScannedEmail.rechecks < max_rechecks)
                .where(ScannedEmail.scanned_at <= now - min_age)
                .where(ScannedEmail.scanned_at >= now - max_age)
                .order_by(ScannedEmail.id)
                .limit(limit)
            )
            return list(s.exec(query))

    def recent(self, limit: int = 20, level: Level | None = None) -> list[ScannedEmail]:
        with Session(self.engine) as s:
            query = select(ScannedEmail).order_by(ScannedEmail.id.desc()).limit(limit)  # type: ignore[union-attr]
            if level is not None:
                query = query.where(ScannedEmail.level == level)
            return list(s.exec(query))

    def _by_id(self, provider: str, provider_id: str):
        return select(ScannedEmail).where(
            ScannedEmail.provider == provider, ScannedEmail.provider_id == provider_id
        )

    def _upsert(self, row: ScannedEmail) -> ScannedEmail:
        """Insert, or replace an earlier result for the same message (e.g. a rescan)."""
        with Session(self.engine) as s:
            existing = s.exec(self._by_id(row.provider, row.provider_id)).first()
            if existing:
                for field, value in row.model_dump(exclude={"id"}).items():
                    setattr(existing, field, value)
                row = existing
            s.add(row)
            s.commit()
            s.refresh(row)
            return row
