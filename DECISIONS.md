# Design decisions

## 2026-11-18: Port optional release-tree traversal

**Decision method:** AI decision (Codex); fresh Claude review required before merge.
**Issue:** [#43](https://github.com/CloudSecurityAlliance/SecID-Server-API/issues/43).

Port SecID-Service ADR-021 to the Python resolver. A source can keep live item
children and optional release branches marked `data.type: "version"` with a
`children` array. Explicit versions select their own tree; missing items/releases
never substitute live content. Version branches do not participate as ordinary
items in scoped or cross-source searches. Version-shaped leaves remain items.
The existing required-version layout is preserved. Test both lazy and bulk loaders.

Rejected: diverging Python behavior, forcing versions on ordinary CWE searches,
or returning live URLs under a historical version. Service is the behavioral
reference and merges first; the CWE registry train follows compatible resolvers.
