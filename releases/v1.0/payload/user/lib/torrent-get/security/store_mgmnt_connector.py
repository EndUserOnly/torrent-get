#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from approval_store import (
    ApprovalIdentity,
    ApprovalStatus,
    ApprovalStore,
    ManifestStatus,
)


@dataclass(frozen=True)
class ManagementSecurityState:
    state: str
    reason: str
    missing: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()
    type_mismatches: tuple[str, ...] = ()


def inspect_security_state(
    store: ApprovalStore,
    identity: ApprovalIdentity,
    payload_root: Path | str | None = None,
    allowed_artifacts: tuple[str, ...] = (),
) -> ManagementSecurityState:

    approval=store.check(identity)

    if approval.status is ApprovalStatus.MISSING:
        return ManagementSecurityState(
            "UNVERIFIED",
            approval.reason,
        )

    if approval.status is ApprovalStatus.CORRUPT:
        return ManagementSecurityState(
            "CORRUPT",
            approval.reason,
        )

    if approval.status is ApprovalStatus.MISMATCH:
        return ManagementSecurityState(
            "MISMATCH",
            approval.reason,
        )

    manifest=store.check_manifest_record(
        identity
    )

    if manifest.status is ManifestStatus.MISSING:
        return ManagementSecurityState(
            "UNVERIFIED",
            manifest.reason,
        )

    if manifest.status is ManifestStatus.CORRUPT:
        return ManagementSecurityState(
            "CORRUPT",
            manifest.reason,
        )

    if manifest.status is ManifestStatus.MISMATCH:
        return ManagementSecurityState(
            "MISMATCH",
            manifest.reason,
        )

    if payload_root is None:
        return ManagementSecurityState(
            "APPROVED",
            "approval and manifest persistence verified",
        )

    payload=store.reconcile_payload(
        identity,
        payload_root,
        allowed_artifacts,
    )

    if payload.status is ManifestStatus.MATCH:
        return ManagementSecurityState(
            "APPROVED",
            payload.reason,
        )

    if payload.status is ManifestStatus.CORRUPT:
        return ManagementSecurityState(
            "CORRUPT",
            payload.reason,
        )

    if payload.unexpected:
        state="PAYLOAD-EXTRA"
    elif payload.missing:
        state="PAYLOAD-MISSING"
    else:
        state="MISMATCH"

    return ManagementSecurityState(
        state,
        payload.reason,
        missing=payload.missing,
        unexpected=payload.unexpected,
        type_mismatches=
            payload.type_mismatches,
    )
