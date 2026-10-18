# Private Gitea validation

VM300 is the private primary source. Its personal-only runner validates exact
`main` source, runs official hassfest, and retains a private Git source ZIP with
per-source provenance. The original tests run with external sockets disabled and only their isolated fixtures.

The workflow does not log into accounts, scan real configuration or secrets,
operate devices, install Home Assistant, publish a release or modify business
data. Existing component code, versions and public distribution links remain
unchanged. It adds no provider credential or source writer. Historical releases
and original branch/tag references stay preserved.

Keep GitHub recovery visibility and Actions disabled. The public HACS credential
validation and installed-consumer distribution path remain separate gates; a
private candidate alone does not certify production installation or public
release readiness. No new periodic schedule is inferred or enabled here.
