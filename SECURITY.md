# Security Policy

homing-format decides whether code may be installed on a device, so security reports are taken
seriously.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/trevortomlin/homing-format/security/advisories/new)
(the "Security" tab, then "Report a vulnerability"), or email **trevortomlin2@outlook.com**.

Please include a description, the affected version or commit, and a reproducer if possible
(for example, a package file that is accepted but should be rejected). You can expect an
acknowledgement within 7 days. Once a fix is available, we will coordinate disclosure with you
and credit you, unless you prefer otherwise.

## Scope

In scope: signature verification, key and trust-store handling, manifest validation, archive
extraction and path handling, the deterministic writer, and device compatibility and
anti-rollback checks. In short, any way to get a package accepted that should be rejected, or
to write outside the staging directory.

Out of scope: the documented limits of the format (no signature expiry, no key revocation yet).
See "Security model and limits" in the README.

## Supported versions

homing-format is pre-alpha and has not been audited. Until 1.0, only the latest commit on
`main` (and later the latest release) receives fixes.
