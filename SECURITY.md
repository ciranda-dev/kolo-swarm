# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, pull
requests or discussions.

Report them privately through GitHub:
[open a private security advisory](https://github.com/ciranda-dev/kolo-swarm/security/advisories/new)
(Security tab, "Report a vulnerability"). Only the maintainers can see it.

Include a description of the issue, the affected version and, if possible,
steps to reproduce it. We will acknowledge your report and keep you updated
while we work on a fix.

If private reporting is not available, open a public issue that only asks
for a private contact, with no details about the vulnerability.

## What a relay operator sees

With `Config.Relays` set, every listed kolo-relay learns the key, address
and online time of a member while it announces a topic (it reserves at
each), which keys talk through that relay, when and how much, and the
target key of every relay dial, also of keys that are not on it. It cannot
read or change relayed traffic: each side runs its own kolo-secure
connection end to end. It never sees topics. It can drop, delay or end the
sessions it carries. With an empty list no relay is contacted.

## Supported versions

This library is experimental and at v0, so its API may change. Only the
latest v0.x release receives security fixes.
