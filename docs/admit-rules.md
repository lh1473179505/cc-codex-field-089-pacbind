# Admit rules

Reuse `load_json`. The bundle is a parsed AP-REQ snapshot: `ticket`, `authenticator`, `pac`, `replay`, and `now`. This lab does not speak ASN.1. HMAC-SHA256 keys are in `--keys` as `service` and `kdc`. Checksums are lowercase hex.

The PAC body used for signing is `json.dumps({k:v for k,v in pac.items() if k != "checksums"}, sort_keys=True, separators=(",", ":"))` as UTF-8. `checksums.server` is HMAC-SHA256 of that body with the service key. `checksums.kdc` is HMAC-SHA256 of the body bytes *concatenated with* the raw bytes of the server checksum hex (decoded as hex) with the KDC key.

## Ticket and authenticator

`authenticator.cname` / `crealm` must equal `ticket.cname` / `crealm` (case-insensitive) (`cname_mismatch`). `authenticator.ctime` must be within `policy.clock_skew` seconds of `now` (default 300) (`clock_skew`). `ticket.endtime` must be `>= now` (`ticket_expired`).

`--replay.used` is a list of `{cname, ctime, cusec}`. A match against the authenticator is `replay`.

## Checksums and groups

A bad or missing service checksum is `server_checksum`. A bad or missing KDC checksum is `kdc_checksum`. If the service checksum passes but the KDC checksum fails, also emit `group_tamper` — the group list is not trusted when only the service checksum is intact.

## Constrained delegation

If `ticket.flags.constrained_delegation` is true, or `pac.delegation` is present, the PAC must contain `delegation.service` that is listed in `policy.allowed_to_delegate`, and `delegation.evidence.cname` must be present. Otherwise `delegation_denied`.

## Report and exit

Report: `decision`, `reason_codes`, `notes`. Stable order: `cname_mismatch`, `clock_skew`, `replay`, `ticket_expired`, `server_checksum`, `kdc_checksum`, `group_tamper`, `delegation_denied`.

`allow` exits 0, `deny` exits 1, load failures exit 2.

## Public fixtures

`--policy fixtures/policy.json --keys fixtures/keys.json --bundle fixtures/bundles/NAME.json`:

- `ok-logon.json` → allow
- `group-edit.json` → deny `group_tamper`
- `replay.json` → deny `replay`
- `clock-skew.json` → deny `clock_skew`
- `cname-mismatch.json` → deny `cname_mismatch`
- `ticket-expired.json` → deny `ticket_expired`
- `ok-delegate.json` → allow
- `delegate-denied.json` → deny `delegation_denied`
- `server-checksum.json` → deny `server_checksum`
