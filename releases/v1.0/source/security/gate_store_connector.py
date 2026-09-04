#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from approval_store import (
    ApprovalIdentity,
    ApprovalStatus,
    ApprovalStore,
    ManifestStatus,
)


class GateStoreDecision(str, Enum):
    APPROVED_EXISTING="APPROVED_EXISTING"
    APPROVED_NEW="APPROVED_NEW"
    DENIED_GATE="DENIED_GATE"
    DENIED_IDENTITY="DENIED_IDENTITY"
    DENIED_STORE="DENIED_STORE"


@dataclass(frozen=True)
class GateApprovalPackage:
    accepted: bool
    infohash: str
    metadata_fingerprint: str
    manifest: tuple[dict[str, Any], ...]
    validator_version: int


@dataclass(frozen=True)
class GateStoreResult:
    decision: GateStoreDecision
    reason: str
    identity: ApprovalIdentity | None = None


def build_identity(
    package: GateApprovalPackage,
    store: ApprovalStore,
) -> ApprovalIdentity:

    if not package.accepted:
        raise ValueError(
            "gate did not accept metadata"
        )

    manifest=store._normalize_manifest(
        list(package.manifest)
    )

    fingerprint=store.manifest_fingerprint(
        list(manifest)
    )

    return ApprovalIdentity(
        infohash=package.infohash,
        metadata_fingerprint=
            package.metadata_fingerprint,
        manifest_fingerprint=fingerprint,
        file_count=len(manifest),
        total_size=sum(
            int(item["size"])
            for item in manifest
        ),
        validator_version=
            package.validator_version,
    ).normalized()


def authorize_gate_result(
    package: GateApprovalPackage,
    store: ApprovalStore,
    approved_at: str | None = None,
) -> GateStoreResult:

    if not package.accepted:
        return GateStoreResult(
            GateStoreDecision.DENIED_GATE,
            "metadata gate rejected admission",
        )

    try:
        identity=build_identity(
            package,
            store,
        )
    except Exception as exc:
        return GateStoreResult(
            GateStoreDecision.DENIED_IDENTITY,
            f"approval identity rejected: {exc}",
        )

    approval=store.check(identity)

    if approval.status is ApprovalStatus.CORRUPT:
        return GateStoreResult(
            GateStoreDecision.DENIED_STORE,
            approval.reason,
            identity,
        )

    if approval.status is ApprovalStatus.MISMATCH:
        return GateStoreResult(
            GateStoreDecision.DENIED_IDENTITY,
            approval.reason,
            identity,
        )

    if approval.status is ApprovalStatus.APPROVED:
        manifest=store.check_manifest_record(
            identity
        )

        if manifest.status is not ManifestStatus.MATCH:
            return GateStoreResult(
                GateStoreDecision.DENIED_STORE,
                manifest.reason,
                identity,
            )

        return GateStoreResult(
            GateStoreDecision.APPROVED_EXISTING,
            "exact persisted approval and manifest matched",
            identity,
        )

    if approved_at is None:
        approved_at=datetime.now(
            timezone.utc
        ).isoformat()

    try:
        store.record(
            identity,
            approved_at,
        )

        store.record_manifest(
            identity,
            list(package.manifest),
        )

    except Exception as exc:
        return GateStoreResult(
            GateStoreDecision.DENIED_STORE,
            f"approval persistence failed: {exc}",
            identity,
        )

    if (
        store.check(identity).status
        is not ApprovalStatus.APPROVED
        or store.check_manifest_record(identity).status
        is not ManifestStatus.MATCH
    ):
        return GateStoreResult(
            GateStoreDecision.DENIED_STORE,
            "post-write approval verification failed",
            identity,
        )

    return GateStoreResult(
        GateStoreDecision.APPROVED_NEW,
        "new approval persisted and verified",
        identity,
    )
