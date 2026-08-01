# Event Families

The current contract is `gargoyle.event/v2`.

## Runtime

- `agent.started`
- `agent.stopped`
- `agent.heartbeat`
- `collector.error`

## Process

- `process.start`
- `process.stop`
- `process.audit_start` (Windows Security event 4688)

Process context may include identity, session, command line, start key, and an executable fingerprint.

## Network

- `network.listen`
- `network.connect`
- `network.listener_closed`
- `network.closed`

Network events may include both `network.owning_pid` and a correlated `process` context.

## Filesystem

- `file.observed`
- `file.created`
- `file.modified`
- `file.deleted`
- `identity.database_changed`
- `identity.credential_database_changed`
- `auth.sudoers_changed`
- `auth.ssh_config_changed`
- `auth.ssh_artifact_changed`
- `network.hosts_file_changed`

## Semantic identity

- `identity.user_observed`
- `identity.user_added`
- `identity.user_removed`
- `identity.user_changed`
- `identity.group_observed`
- `identity.group_added`
- `identity.group_removed`
- `identity.group_changed`
- `identity.group_membership_changed`

`identity.group_membership_changed` includes sorted `added_members` and
`removed_members` arrays in `data`. Changes to other group attributes remain
`identity.group_changed`.

## Authentication

- `auth.login_success`
- `auth.login_failure`
- `auth.privilege_use`
- `auth.privilege_failure`
- `auth.explicit_credentials`
- `auth.privileged_logon`

The `auth` context normalizes outcome, mechanism, account, domain, logon type, source endpoint, workstation, authentication package, logon ID, failure reason, record ID, and privileges where available.

Windows event 4648 records an explicit-credential attempt, not proof that the
target authentication succeeded, so GARGOYLE emits it with `outcome =
"unknown"`.

## Kernel

- `kernel.module_loaded`
- `kernel.module_unloaded`
- `kernel.taint_changed`
- `kernel.lockdown_changed`

## v2 compatibility rules

Within `gargoyle.event/v2`:

- required field meanings do not change
- optional fields and event kinds may be added
- platform-specific absence is represented by omitted optional fields
- removing fields or changing required semantics requires another schema bump
- polling and future event-driven backends must preserve semantic event kinds
