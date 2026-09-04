#!/usr/bin/env python3

"""
torrent-get approval-store

Standalone persistent approval-state module.

This module deliberately knows nothing about:
- libtorrent
- magnets
- peers
- trackers
- workers
- queue dispatch
- payload release

Its job is only to answer:

    Has this exact approval identity been persisted before?

Security properties:
- JSON program-owned state
- one record per torrent identity
- atomic replace
- fsync before publication
- directory fsync after publication
- mode 0600 records
- mode 0700 state directory
- record integrity digest
- schema/version checks
- validator-version binding
- corrupt state fails closed
- mismatch never becomes approval
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


STORE_FORMAT_VERSION = 1


class ApprovalStatus(str, Enum):
    APPROVED = "APPROVED"
    MISSING = "MISSING"
    MISMATCH = "MISMATCH"
    CORRUPT = "CORRUPT"


@dataclass(frozen=True)
class ApprovalIdentity:
    """
    Immutable facts supplied by the future metadata gate.

    approval-store does not calculate these values.
    The caller will eventually derive them.
    """

    infohash: str
    metadata_fingerprint: str
    manifest_fingerprint: str
    file_count: int
    total_size: int
    validator_version: int

    def normalized(self) -> "ApprovalIdentity":
        infohash = self.infohash.strip().lower()
        metadata = self.metadata_fingerprint.strip().lower()
        manifest = self.manifest_fingerprint.strip().lower()

        if not infohash:
            raise ValueError("empty infohash")

        if not metadata:
            raise ValueError("empty metadata fingerprint")

        if not manifest:
            raise ValueError("empty manifest fingerprint")

        if self.file_count < 0:
            raise ValueError("negative file count")

        if self.total_size < 0:
            raise ValueError("negative total size")

        if self.validator_version < 1:
            raise ValueError("invalid validator version")

        return ApprovalIdentity(
            infohash=infohash,
            metadata_fingerprint=metadata,
            manifest_fingerprint=manifest,
            file_count=int(self.file_count),
            total_size=int(self.total_size),
            validator_version=int(self.validator_version),
        )


@dataclass(frozen=True)
class ApprovalRecord:
    format_version: int
    identity: ApprovalIdentity
    approved_at: str
    digest: str


@dataclass(frozen=True)
class ApprovalCheck:
    status: ApprovalStatus
    reason: str
    record: ApprovalRecord | None = None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _record_body(
    identity: ApprovalIdentity,
    approved_at: str,
) -> dict[str, Any]:
    return {
        "format_version": STORE_FORMAT_VERSION,
        "identity": asdict(identity.normalized()),
        "approved_at": approved_at,
    }


def _digest_body(body: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json(body)
    ).hexdigest()


def _parse_record(raw: Any) -> ApprovalRecord:
    if not isinstance(raw, dict):
        raise ValueError("record is not an object")

    if set(raw) != {
        "format_version",
        "identity",
        "approved_at",
        "digest",
    }:
        raise ValueError("unexpected record fields")

    if raw["format_version"] != STORE_FORMAT_VERSION:
        raise ValueError("unsupported store format version")

    identity_raw = raw["identity"]

    if not isinstance(identity_raw, dict):
        raise ValueError("identity is not an object")

    expected_identity_fields = {
        "infohash",
        "metadata_fingerprint",
        "manifest_fingerprint",
        "file_count",
        "total_size",
        "validator_version",
    }

    if set(identity_raw) != expected_identity_fields:
        raise ValueError("unexpected identity fields")

    identity = ApprovalIdentity(
        infohash=str(identity_raw["infohash"]),
        metadata_fingerprint=str(
            identity_raw["metadata_fingerprint"]
        ),
        manifest_fingerprint=str(
            identity_raw["manifest_fingerprint"]
        ),
        file_count=int(identity_raw["file_count"]),
        total_size=int(identity_raw["total_size"]),
        validator_version=int(
            identity_raw["validator_version"]
        ),
    ).normalized()

    approved_at = raw["approved_at"]

    if not isinstance(approved_at, str) or not approved_at:
        raise ValueError("invalid approval timestamp")

    body = _record_body(identity, approved_at)

    expected_digest = _digest_body(body)
    supplied_digest = raw["digest"]

    if not isinstance(supplied_digest, str):
        raise ValueError("invalid digest")

    if not hmac.compare_digest(
        expected_digest,
        supplied_digest.lower(),
    ):
        raise ValueError("record digest mismatch")

    return ApprovalRecord(
        format_version=STORE_FORMAT_VERSION,
        identity=identity,
        approved_at=approved_at,
        digest=expected_digest,
    )



class ManifestStatus(str, Enum):
    MATCH = "MATCH"
    MISSING = "MISSING"
    MISMATCH = "MISMATCH"
    CORRUPT = "CORRUPT"


@dataclass(frozen=True)
class ManifestCheck:
    status: ManifestStatus
    reason: str
    missing: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()
    type_mismatches: tuple[str, ...] = ()


class ApprovalStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)

    def ensure(self) -> None:
        self.root.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

        os.chmod(self.root, 0o700)

    @staticmethod
    def _key(infohash: str) -> str:
        normalized = infohash.strip().lower()

        if not normalized:
            raise ValueError("empty infohash")

        return hashlib.sha256(
            normalized.encode("utf-8")
        ).hexdigest()

    def path_for(
        self,
        identity: ApprovalIdentity,
    ) -> Path:
        normalized = identity.normalized()

        return self.root / (
            self._key(normalized.infohash) + ".json"
        )

    def check(
        self,
        identity: ApprovalIdentity,
    ) -> ApprovalCheck:
        expected = identity.normalized()
        path = self.path_for(expected)

        if not path.exists():
            return ApprovalCheck(
                ApprovalStatus.MISSING,
                "approval record does not exist",
            )

        try:
            raw = json.loads(
                path.read_text(encoding="utf-8")
            )

            record = _parse_record(raw)

        except Exception as exc:
            return ApprovalCheck(
                ApprovalStatus.CORRUPT,
                f"approval record rejected: {exc}",
            )

        if record.identity != expected:
            return ApprovalCheck(
                ApprovalStatus.MISMATCH,
                "persisted approval identity differs",
                record,
            )

        return ApprovalCheck(
            ApprovalStatus.APPROVED,
            "exact approval identity matched",
            record,
        )

    def record(
        self,
        identity: ApprovalIdentity,
        approved_at: str,
    ) -> ApprovalRecord:
        identity = identity.normalized()

        if not isinstance(approved_at, str):
            raise ValueError("approval timestamp must be text")

        approved_at = approved_at.strip()

        if not approved_at:
            raise ValueError("empty approval timestamp")

        self.ensure()

        body = _record_body(
            identity,
            approved_at,
        )

        payload = {
            **body,
            "digest": _digest_body(body),
        }

        encoded = (
            json.dumps(
                payload,
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")

        target = self.path_for(identity)

        fd = -1
        temp_path: Path | None = None

        try:
            fd, temp_name = tempfile.mkstemp(
                prefix=".approval-",
                suffix=".tmp",
                dir=self.root,
            )

            temp_path = Path(temp_name)

            os.fchmod(fd, 0o600)

            with os.fdopen(
                fd,
                "wb",
                closefd=True,
            ) as handle:
                fd = -1

                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(
                temp_path,
                target,
            )

            temp_path = None

            os.chmod(target, 0o600)

            directory_fd = os.open(
                self.root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0),
            )

            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        finally:
            if fd >= 0:
                os.close(fd)

            if (
                temp_path is not None
                and temp_path.exists()
            ):
                temp_path.unlink()

        result = self.check(identity)

        if result.status is not ApprovalStatus.APPROVED:
            raise RuntimeError(
                "post-write approval verification failed: "
                + result.reason
            )

        assert result.record is not None
        return result.record

    def invalidate(
        self,
        identity: ApprovalIdentity,
    ) -> bool:
        path = self.path_for(identity)

        try:
            path.unlink()
        except FileNotFoundError:
            return False

        if self.root.exists():
            directory_fd = os.open(
                self.root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0),
            )

            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        return True

    def list_records(self) -> list[ApprovalRecord]:
        if not self.root.exists():
            return []

        records: list[ApprovalRecord] = []

        for path in sorted(
            self.root.glob("*.json")
        ):
            try:
                raw = json.loads(
                    path.read_text(encoding="utf-8")
                )

                records.append(
                    _parse_record(raw)
                )

            except Exception:
                # Listing cannot transform corrupt state
                # into trusted state.
                continue

        return records



    @staticmethod
    def _normalize_manifest(
        entries: list[dict[str, Any]]
        | tuple[dict[str, Any], ...],
    ) -> tuple[dict[str, Any], ...]:
        """
        Canonical approved payload namespace.

        approval-store owns this representation.
        """

        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()

        for raw in entries:
            if not isinstance(raw, dict):
                raise ValueError(
                    "manifest entry is not an object"
                )

            if set(raw) != {"path", "size"}:
                raise ValueError(
                    "unexpected manifest entry fields"
                )

            path = str(raw["path"]).strip()

            if not path:
                raise ValueError(
                    "empty manifest path"
                )

            if path.startswith("/"):
                raise ValueError(
                    "absolute manifest path"
                )

            if "\\" in path:
                raise ValueError(
                    "non-canonical path separator"
                )

            parts = path.split("/")

            if any(
                part in {"", ".", ".."}
                for part in parts
            ):
                raise ValueError(
                    "unsafe manifest component"
                )

            if any("\x00" in part for part in parts):
                raise ValueError(
                    "NUL in manifest path"
                )

            canonical = "/".join(parts)

            if canonical in seen:
                raise ValueError(
                    "duplicate normalized path"
                )

            seen.add(canonical)

            size = int(raw["size"])

            if size < 0:
                raise ValueError(
                    "negative manifest size"
                )

            normalized.append(
                {
                    "path": canonical,
                    "size": size,
                }
            )

        normalized.sort(
            key=lambda item: item["path"]
        )

        file_paths = {
            item["path"]
            for item in normalized
        }

        for path in file_paths:
            parts = path.split("/")

            for i in range(1, len(parts)):
                prefix="/".join(parts[:i])

                if prefix in file_paths:
                    raise ValueError(
                        "file-directory path conflict"
                    )

        return tuple(normalized)

    @staticmethod
    def manifest_fingerprint(
        entries: list[dict[str, Any]]
        | tuple[dict[str, Any], ...],
    ) -> str:
        normalized=ApprovalStore._normalize_manifest(
            entries
        )

        return hashlib.sha256(
            _canonical_json(
                {
                    "manifest_version": 1,
                    "files": normalized,
                }
            )
        ).hexdigest()

    def manifest_path_for(
        self,
        identity: ApprovalIdentity,
    ) -> Path:
        identity=identity.normalized()

        return self.root / (
            self._key(identity.infohash)
            + ".manifest.json"
        )

    def record_manifest(
        self,
        identity: ApprovalIdentity,
        entries: list[dict[str, Any]]
        | tuple[dict[str, Any], ...],
    ) -> None:
        """
        Persist the exact canonical payload namespace approved
        for this identity.
        """

        identity=identity.normalized()
        normalized=self._normalize_manifest(entries)

        file_count=len(normalized)
        total_size=sum(
            int(item["size"])
            for item in normalized
        )

        fingerprint=self.manifest_fingerprint(
            list(normalized)
        )

        if file_count != identity.file_count:
            raise ValueError(
                "manifest file_count differs from identity"
            )

        if total_size != identity.total_size:
            raise ValueError(
                "manifest total_size differs from identity"
            )

        if fingerprint != identity.manifest_fingerprint:
            raise ValueError(
                "manifest fingerprint differs from identity"
            )

        self.ensure()

        body={
            "format_version": 1,
            "infohash": identity.infohash,
            "validator_version": identity.validator_version,
            "file_count": file_count,
            "total_size": total_size,
            "manifest_fingerprint": fingerprint,
            "files": list(normalized),
        }

        payload={
            **body,
            "digest": _digest_body(body),
        }

        encoded=(
            json.dumps(
                payload,
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")

        target=self.manifest_path_for(identity)

        fd=-1
        temp_path: Path | None=None

        try:
            fd,temp_name=tempfile.mkstemp(
                prefix=".manifest-",
                suffix=".tmp",
                dir=self.root,
            )

            temp_path=Path(temp_name)

            os.fchmod(fd,0o600)

            with os.fdopen(
                fd,
                "wb",
                closefd=True,
            ) as handle:
                fd=-1

                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(
                temp_path,
                target,
            )

            temp_path=None

            os.chmod(target,0o600)

            directory_fd=os.open(
                self.root,
                os.O_RDONLY
                | getattr(os,"O_DIRECTORY",0),
            )

            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        finally:
            if fd >= 0:
                os.close(fd)

            if (
                temp_path is not None
                and temp_path.exists()
            ):
                temp_path.unlink()

        check=self.check_manifest_record(identity)

        if check.status is not ManifestStatus.MATCH:
            raise RuntimeError(
                "post-write manifest verification failed: "
                + check.reason
            )

    def check_manifest_record(
        self,
        identity: ApprovalIdentity,
    ) -> ManifestCheck:
        """
        Verify persisted manifest record integrity and identity.
        """

        identity=identity.normalized()
        path=self.manifest_path_for(identity)

        if not path.exists():
            return ManifestCheck(
                ManifestStatus.MISSING,
                "manifest record does not exist",
            )

        try:
            raw=json.loads(
                path.read_text(encoding="utf-8")
            )

            expected_fields={
                "format_version",
                "infohash",
                "validator_version",
                "file_count",
                "total_size",
                "manifest_fingerprint",
                "files",
                "digest",
            }

            if not isinstance(raw,dict):
                raise ValueError(
                    "manifest record is not an object"
                )

            if set(raw) != expected_fields:
                raise ValueError(
                    "unexpected manifest record fields"
                )

            if raw["format_version"] != 1:
                raise ValueError(
                    "unsupported manifest format"
                )

            files=self._normalize_manifest(
                raw["files"]
            )

            body={
                "format_version": 1,
                "infohash": str(
                    raw["infohash"]
                ).strip().lower(),
                "validator_version": int(
                    raw["validator_version"]
                ),
                "file_count": int(
                    raw["file_count"]
                ),
                "total_size": int(
                    raw["total_size"]
                ),
                "manifest_fingerprint": str(
                    raw["manifest_fingerprint"]
                ).strip().lower(),
                "files": list(files),
            }

            expected_digest=_digest_body(body)

            if not hmac.compare_digest(
                expected_digest,
                str(raw["digest"]).lower(),
            ):
                raise ValueError(
                    "manifest digest mismatch"
                )

            fingerprint=self.manifest_fingerprint(
                list(files)
            )

            if fingerprint != body[
                "manifest_fingerprint"
            ]:
                raise ValueError(
                    "manifest fingerprint mismatch"
                )

            total_size=sum(
                int(item["size"])
                for item in files
            )

            if len(files) != body["file_count"]:
                raise ValueError(
                    "manifest file count inconsistent"
                )

            if total_size != body["total_size"]:
                raise ValueError(
                    "manifest total size inconsistent"
                )

        except Exception as exc:
            return ManifestCheck(
                ManifestStatus.CORRUPT,
                f"manifest record rejected: {exc}",
            )

        if (
            body["infohash"] != identity.infohash
            or body["validator_version"]
                != identity.validator_version
            or body["file_count"]
                != identity.file_count
            or body["total_size"]
                != identity.total_size
            or body["manifest_fingerprint"]
                != identity.manifest_fingerprint
        ):
            return ManifestCheck(
                ManifestStatus.MISMATCH,
                "manifest record differs from approval identity",
            )

        return ManifestCheck(
            ManifestStatus.MATCH,
            "persisted manifest exactly matches approval identity",
        )

    def load_manifest(
        self,
        identity: ApprovalIdentity,
    ) -> tuple[dict[str, Any], ...]:
        check=self.check_manifest_record(identity)

        if check.status is not ManifestStatus.MATCH:
            raise RuntimeError(
                check.reason
            )

        raw=json.loads(
            self.manifest_path_for(
                identity
            ).read_text(
                encoding="utf-8"
            )
        )

        return self._normalize_manifest(
            raw["files"]
        )

    def reconcile_payload(
        self,
        identity: ApprovalIdentity,
        payload_root: Path | str,
        allowed_artifacts: tuple[str, ...] = (),
    ) -> ManifestCheck:
        """
        Compare actual filesystem objects against the persisted
        approved payload namespace.

        Nothing undeclared is silently adopted.
        """

        identity=identity.normalized()

        approval=self.check(identity)

        if approval.status is not ApprovalStatus.APPROVED:
            return ManifestCheck(
                ManifestStatus.CORRUPT
                if approval.status is ApprovalStatus.CORRUPT
                else ManifestStatus.MISMATCH,
                "approval record is not trusted: "
                + approval.reason,
            )

        manifest_check=self.check_manifest_record(
            identity
        )

        if manifest_check.status is not ManifestStatus.MATCH:
            return manifest_check

        root=Path(payload_root)

        if not root.exists():
            return ManifestCheck(
                ManifestStatus.MISMATCH,
                "payload root missing",
                missing=tuple(
                    item["path"]
                    for item in self.load_manifest(
                        identity
                    )
                ),
            )

        if not root.is_dir():
            return ManifestCheck(
                ManifestStatus.MISMATCH,
                "payload root is not a directory",
                type_mismatches=(".",),
            )

        expected={
            item["path"]
            for item in self.load_manifest(identity)
        }

        allowed=set(allowed_artifacts)

        observed: set[str]=set()
        special: set[str]=set()

        for current,dirs,files in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current_path=Path(current)

            keep_dirs=[]

            for name in dirs:
                absolute=current_path/name
                relative=absolute.relative_to(
                    root
                ).as_posix()

                if absolute.is_symlink():
                    special.add(relative)
                else:
                    keep_dirs.append(name)

            dirs[:]=keep_dirs

            for name in files:
                absolute=current_path/name
                relative=absolute.relative_to(
                    root
                ).as_posix()

                if absolute.is_symlink():
                    special.add(relative)
                elif absolute.is_file():
                    observed.add(relative)
                else:
                    special.add(relative)

        missing=tuple(
            sorted(expected-observed)
        )

        unexpected=tuple(
            sorted(
                observed
                - expected
                - allowed
            )
        )

        type_mismatches=tuple(
            sorted(
                special
                - allowed
            )
        )

        if (
            missing
            or unexpected
            or type_mismatches
        ):
            return ManifestCheck(
                ManifestStatus.MISMATCH,
                "payload does not close against approved manifest",
                missing=missing,
                unexpected=unexpected,
                type_mismatches=type_mismatches,
            )

        return ManifestCheck(
            ManifestStatus.MATCH,
            "payload exactly closes against approved manifest",
        )


def _selftest() -> None:
    """
    Synthetic test only.

    No swarm, torrent, queue or production state is touched.
    """

    with tempfile.TemporaryDirectory(
        prefix="torrent-get-approval-store-test-"
    ) as td:

        root = Path(td) / "approvals"
        store = ApprovalStore(root)

        identity = ApprovalIdentity(
            infohash="ABCDEF0123456789",
            metadata_fingerprint="11" * 32,
            manifest_fingerprint="22" * 32,
            file_count=7,
            total_size=123456789,
            validator_version=1,
        )

        # -------------------------------------------------
        # Missing
        # -------------------------------------------------

        result = store.check(identity)

        assert result.status is ApprovalStatus.MISSING

        print("PASS: MISSING fails closed")

        # -------------------------------------------------
        # Record + exact match
        # -------------------------------------------------

        record = store.record(
            identity,
            "2026-08-13T17:18:00+00:00",
        )

        assert record.identity == identity.normalized()

        result = store.check(identity)

        assert result.status is ApprovalStatus.APPROVED

        print("PASS: exact identity APPROVED")

        # Permissions.
        mode = (
            store.path_for(identity).stat().st_mode
            & 0o777
        )

        assert mode == 0o600

        directory_mode = root.stat().st_mode & 0o777

        assert directory_mode == 0o700

        print("PASS: 0600 record / 0700 directory")

        # -------------------------------------------------
        # Metadata mismatch
        # -------------------------------------------------

        changed_metadata = ApprovalIdentity(
            infohash=identity.infohash,
            metadata_fingerprint="33" * 32,
            manifest_fingerprint=identity.manifest_fingerprint,
            file_count=identity.file_count,
            total_size=identity.total_size,
            validator_version=identity.validator_version,
        )

        result = store.check(changed_metadata)

        assert result.status is ApprovalStatus.MISMATCH

        print("PASS: metadata mismatch rejected")

        # -------------------------------------------------
        # Manifest mismatch
        # -------------------------------------------------

        changed_manifest = ApprovalIdentity(
            infohash=identity.infohash,
            metadata_fingerprint=identity.metadata_fingerprint,
            manifest_fingerprint="44" * 32,
            file_count=identity.file_count,
            total_size=identity.total_size,
            validator_version=identity.validator_version,
        )

        result = store.check(changed_manifest)

        assert result.status is ApprovalStatus.MISMATCH

        print("PASS: manifest mismatch rejected")

        # -------------------------------------------------
        # Validator-version mismatch
        # -------------------------------------------------

        changed_validator = ApprovalIdentity(
            infohash=identity.infohash,
            metadata_fingerprint=identity.metadata_fingerprint,
            manifest_fingerprint=identity.manifest_fingerprint,
            file_count=identity.file_count,
            total_size=identity.total_size,
            validator_version=2,
        )

        result = store.check(changed_validator)

        assert result.status is ApprovalStatus.MISMATCH

        print("PASS: validator-version mismatch rejected")

        # -------------------------------------------------
        # Corruption
        # -------------------------------------------------

        target = store.path_for(identity)
        original = target.read_bytes()

        target.write_text(
            '{"broken":true}\n',
            encoding="utf-8",
        )

        result = store.check(identity)

        assert result.status is ApprovalStatus.CORRUPT

        print("PASS: corrupt state fails closed")

        target.write_bytes(original)

        assert (
            store.check(identity).status
            is ApprovalStatus.APPROVED
        )

        # -------------------------------------------------
        # Digest tamper
        # -------------------------------------------------

        raw = json.loads(
            target.read_text(encoding="utf-8")
        )

        raw["identity"]["total_size"] += 1

        target.write_text(
            json.dumps(raw) + "\n",
            encoding="utf-8",
        )

        result = store.check(identity)

        assert result.status is ApprovalStatus.CORRUPT

        print("PASS: digest tamper detected")

        # Restore through authoritative record().
        store.record(
            identity,
            "2026-08-13T17:18:01+00:00",
        )

        # -------------------------------------------------
        # Listing
        # -------------------------------------------------

        records = store.list_records()

        assert len(records) == 1
        assert records[0].identity == identity.normalized()

        print("PASS: record listing")

        # -------------------------------------------------
        # Invalidate
        # -------------------------------------------------

        assert store.invalidate(identity) is True

        result = store.check(identity)

        assert result.status is ApprovalStatus.MISSING

        print("PASS: invalidation returns to MISSING")

        assert store.invalidate(identity) is False

        # No abandoned atomic-write files.
        leftovers = list(
            root.glob(".approval-*.tmp")
        )

        assert leftovers == []

        print("PASS: no temporary-write residue")

    print()
    print("APPROVAL STORE SELF-TEST — PASS")


if __name__ == "__main__":
    _selftest()
