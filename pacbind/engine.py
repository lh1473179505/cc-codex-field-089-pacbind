from __future__ import annotations
import hashlib
import hmac
import json
from typing import Any

REASON_ORDER = [
    "cname_mismatch",
    "clock_skew",
    "replay",
    "ticket_expired",
    "server_checksum",
    "kdc_checksum",
    "group_tamper",
    "delegation_denied",
]


def _pac_body(pac: dict[str, Any]) -> bytes:
    body = {k: v for k, v in pac.items() if k != "checksums"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac(key_hex: str, data: bytes) -> str:
    return hmac.new(bytes.fromhex(key_hex), data, hashlib.sha256).hexdigest()


def admit(bundle: dict[str, Any], policy: dict[str, Any], keys: dict[str, str]) -> dict[str, Any]:
    ticket = bundle.get("ticket") or {}
    authenticator = bundle.get("authenticator") or {}
    pac = bundle.get("pac") or {}
    replay = bundle.get("replay") or {}
    now = bundle.get("now")

    reasons: set[str] = set()
    notes: list[str] = []

    def flag(reason: str, note: str) -> None:
        if reason not in reasons:
            reasons.add(reason)
            notes.append(note)

    if str(authenticator.get("cname", "")).lower() != str(ticket.get("cname", "")).lower() or \
            str(authenticator.get("crealm", "")).lower() != str(ticket.get("crealm", "")).lower():
        flag("cname_mismatch", "authenticator client name/realm does not match the ticket")

    skew = policy.get("clock_skew", 300)
    ctime = authenticator.get("ctime")
    if ctime is None or now is None or abs(ctime - now) > skew:
        flag("clock_skew", "authenticator ctime is outside the allowed clock skew")

    for entry in replay.get("used") or []:
        if (entry.get("cname") == authenticator.get("cname")
                and entry.get("ctime") == authenticator.get("ctime")
                and entry.get("cusec") == authenticator.get("cusec")):
            flag("replay", "authenticator matches an entry in the replay cache")
            break

    endtime = ticket.get("endtime")
    if endtime is None or now is None or endtime < now:
        flag("ticket_expired", "ticket endtime is in the past")

    checksums = pac.get("checksums") or {}
    body = _pac_body(pac)
    server_ok = False
    kdc_ok = False
    server_claimed = checksums.get("server")
    if isinstance(server_claimed, str) and hmac.compare_digest(
            server_claimed.lower(), _hmac(keys["service"], body)):
        server_ok = True
    else:
        flag("server_checksum", "PAC server checksum is missing or invalid")

    kdc_claimed = checksums.get("kdc")
    if server_ok and isinstance(kdc_claimed, str):
        try:
            server_raw = bytes.fromhex(server_claimed)
        except ValueError:
            server_raw = b""
        if server_raw and hmac.compare_digest(
                kdc_claimed.lower(), _hmac(keys["kdc"], body + server_raw)):
            kdc_ok = True
    if not kdc_ok:
        flag("kdc_checksum", "PAC KDC checksum is missing or invalid")
        if server_ok:
            flag("group_tamper", "server checksum is intact but the KDC checksum failed; group list is not trusted")

    delegation = pac.get("delegation")
    if (ticket.get("flags") or {}).get("constrained_delegation") or delegation is not None:
        delegation = delegation or {}
        allowed = policy.get("allowed_to_delegate") or []
        service = delegation.get("service")
        evidence = delegation.get("evidence") or {}
        if service not in allowed or not evidence.get("cname"):
            flag("delegation_denied", "constrained delegation is not permitted by policy")

    reason_codes = [r for r in REASON_ORDER if r in reasons]
    decision = "allow" if not reason_codes else "deny"
    return {"decision": decision, "reason_codes": reason_codes, "notes": notes}
