# pacbind

A Kerberos PAC admission tool for a parsed AP-REQ snapshot (HMAC checksums, replay, constrained delegation).

`python -m pacbind inspect --bundle fixtures/bundles/ok-logon.json` already prints the client and groups. `admit` is still a stub.

Standard library only. No Docker, no real KDC.
