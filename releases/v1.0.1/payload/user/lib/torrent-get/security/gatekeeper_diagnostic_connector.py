#!/usr/bin/env python3

"""
torrent-get Gatekeeper diagnostic connector.

Observes gate_store_connector decisions.

Critical property:

    diagnostic failure NEVER changes the underlying
    Gatekeeper decision.

The original gate_store_connector remains the enforcement
authority.
"""

from __future__ import annotations
import json
import sys
from datetime import datetime, timezone

import time
from typing import Any

import gate_store_connector as enforcement

try:
    import security_diagnostic_log as diagnostic
except Exception:
    diagnostic=None


GateApprovalPackage=enforcement.GateApprovalPackage
GateStoreDecision=enforcement.GateStoreDecision


def _emit(event: str, **fields) -> None:
    """
    Native Gatekeeper diagnostic emission.

    One structured TG_GATE record is written to the worker's
    existing stderr stream. systemd already persists that stream
    in the existing per-job log.

    Diagnostic failure never changes enforcement.
    """
    try:
        record={
            "ts":datetime.now(timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00","Z"),
            "event":str(event).upper(),
        }

        for key,value in fields.items():
            if value is None:
                continue

            record[key]=value

        print(
            "TG_GATE\t"
            + json.dumps(
                record,
                separators=(",",":"),
                sort_keys=True,
                ensure_ascii=False,
            ),
            file=sys.stderr,
            flush=True,
        )

    except Exception:
        pass


def _field(obj: Any, name: str, default=""):
    try:
        return getattr(obj,name)
    except Exception:
        return default


def _decision_name(result) -> str:
    try:
        value=result.decision.value
    except Exception:
        try:
            value=str(result.decision)
        except Exception:
            value=""

    return str(value).upper()


def authorize_gate_result(
    package,
    store,
):
    """
    Exact public interface of gate_store_connector.

    Enforcement result returned unchanged.
    """

    started=time.monotonic()

    job_id=_field(package,"job_id",None)

    torrent_id=_field(
        package,
        "infohash",
        "",
    )

    manifest_digest=_field(
        package,
        "manifest_digest",
        "",
    )

    validator_version=_field(
        package,
        "validator_version",
        "",
    )

    _emit(
        "RECEIVED",
        job_id=job_id,
        torrent_id=torrent_id,
        manifest_digest=manifest_digest,
        validator_version=validator_version,
        reason="gatekeeper request entered store connector",
    )

    _emit(
        "STORE_LOOKUP",
        job_id=job_id,
        torrent_id=torrent_id,
        manifest_digest=manifest_digest,
        validator_version=validator_version,
        reason="persistent approval lookup",
    )

    try:
        # ---------------------------------------------
        # ORIGINAL ENFORCEMENT AUTHORITY
        # ---------------------------------------------
        result=enforcement.authorize_gate_result(
            package,
            store,
        )

    except Exception as exc:
        elapsed=(
            time.monotonic()-started
        )*1000.0

        _emit(
            "ERROR",
            job_id=job_id,
            torrent_id=torrent_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="ERROR",
            reason=(
                f"{type(exc).__name__}: {exc}"
            ),
            elapsed_ms=elapsed,
        )

        _emit(
            "GATE_DENY",
            job_id=job_id,
            torrent_id=torrent_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="DENY",
            reason="gate connector raised exception",
            elapsed_ms=elapsed,
        )

        # Preserve original enforcement behavior.
        raise

    elapsed=(
        time.monotonic()-started
    )*1000.0

    decision=_decision_name(result)

    reason=str(
        _field(result,"reason","")
        or ""
    )

    approval_id=str(
        _field(result,"approval_id","")
        or ""
    )

    # ---------------------------------------------
    # We only emit events justified by the actual
    # decision returned by the enforcement module.
    #
    # No inference from torrent names, peers, etc.
    # ---------------------------------------------

    if "APPROVED_NEW" in decision:

        _emit(
            "STORE_MISSING",
            job_id=job_id,
            torrent_id=torrent_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="PASS",
            reason="no reusable approval; new approval required",
        )

        _emit(
            "APPROVAL_NEW",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="PASS",
            reason=reason,
        )

        _emit(
            "GATE_RELEASE",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="ALLOW",
            reason=reason or "new approval accepted",
            elapsed_ms=elapsed,
        )

    elif "APPROVED_EXISTING" in decision:

        _emit(
            "STORE_MATCH",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="PASS",
            reason="persisted approval matched",
        )

        _emit(
            "MANIFEST_MATCH",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="PASS",
            reason="persisted manifest accepted",
        )

        _emit(
            "APPROVAL_REUSED",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="PASS",
            reason=reason,
        )

        _emit(
            "GATE_RELEASE",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="ALLOW",
            reason=reason or "existing approval accepted",
            elapsed_ms=elapsed,
        )

    else:
        lower_reason=reason.casefold()

        # More specific evidence only when the enforcement
        # reason actually supports it.

        if "manifest" in lower_reason:
            _emit(
                "MANIFEST_MISMATCH",
                job_id=job_id,
                torrent_id=torrent_id,
                approval_id=approval_id,
                manifest_digest=manifest_digest,
                validator_version=validator_version,
                decision="FAIL",
                reason=reason,
            )

        if (
            "undeclared" in lower_reason
            or "piggyback" in lower_reason
        ):
            _emit(
                "PAYLOAD_UNDECLARED",
                job_id=job_id,
                torrent_id=torrent_id,
                decision="FAIL",
                reason=reason,
            )

        if "missing" in lower_reason:
            _emit(
                "PAYLOAD_MISSING",
                job_id=job_id,
                torrent_id=torrent_id,
                decision="FAIL",
                reason=reason,
            )

        if (
            "symlink" in lower_reason
            or "special" in lower_reason
        ):
            _emit(
                "PAYLOAD_SPECIAL",
                job_id=job_id,
                torrent_id=torrent_id,
                decision="FAIL",
                reason=reason,
            )

        _emit(
            "STORE_MISMATCH",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="FAIL",
            reason=reason or decision,
        )

        _emit(
            "GATE_DENY",
            job_id=job_id,
            torrent_id=torrent_id,
            approval_id=approval_id,
            manifest_digest=manifest_digest,
            validator_version=validator_version,
            decision="DENY",
            reason=reason or decision,
            elapsed_ms=elapsed,
        )

    # ---------------------------------------------
    # Absolutely critical:
    # return the ORIGINAL result object unchanged.
    # ---------------------------------------------
    return result
