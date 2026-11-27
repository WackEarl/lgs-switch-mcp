# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-27

### Changed

- Renamed the distribution, Python package, console script, and MCP server
  from `netmiko-mcp-linksys` / `netmiko_mcp_linksys` to `lgs-switch-mcp` /
  `lgs_switch_mcp`. The previous console script and import path remain as
  deprecated aliases so existing hub entries keep working. `SWITCH_*`
  environment variables are unchanged.
- Renamed the GitHub repository to
  [WackEarl/lgs-switch-mcp](https://github.com/WackEarl/lgs-switch-mcp).
  The previous path redirects.

### Added

- GitHub Actions CI for pytest on Python 3.12, 3.13, and 3.14 (in #16).
- README credits and a NOTICE file for netmiko (MIT, Kirk Byers) and
  netmiko-mcp (Apache License 2.0, Kirk Byers) (in #17).

## [0.3.2] - 2026-11-27

### Added

- SSH session handling: at most one SSH session to the switch, shared by
  tool calls and the background config dump. A clean session is kept for
  `SWITCH_SESSION_IDLE` seconds (default 10, `0` = log out after every
  call) and then logged out with `exit`.
- Reconnect protection: after a command timeout or a failed or slow
  connect, no new SSH connection is opened for `SWITCH_COOLDOWN_BASE`
  seconds (default 30, doubling per failure up to `SWITCH_COOLDOWN_MAX`,
  default 600, reset by a successful call, kept in
  `SWITCH_STATE_DIR/ssh-breaker.json` across restarts). Calls answer
  `Switch cooling down …; retry in Ns` without connecting.
- `SWITCH_LOGOUT_TIMEOUT` (default 3 s): time the switch gets to close
  the channel after `exit` before the transport is closed hard.
- Graceful shutdown: the kept session is logged out when the process
  ends (stdin closed, SIGTERM, SIGHUP, interpreter exit).

- `SWITCH_CALL_BUDGET` (default 45 s): wall-clock budget of one tool call
  for the session lock, the connect and every command. A call that runs
  out ends with a tool error instead of the caller's request timeout
  (MCP `-32001`). Applying writes (`dry_run=false`) are not cut by it.
- `SWITCH_CONFIG_DUMP_TIMEOUT` (default 240 s): the running-config dump
  of `config_read`, `config_backup` and `config_diff` runs in the
  background. A dump that takes longer than the call budget answers
  `Pending:`; the next call gets the finished dump once (`read_at`,
  `dump_seconds`, `age_seconds`). A dump from before a configuration
  change through this server is never handed out.
- `health_summary`: `environment_skipped` names environment shows that
  are not on the allowlist.
- `audit_tail`: `unfinished` entries carry `age_ms`.

### Changed

- Ports with an interface prefix (`Gi0/15`, `gi 0/15`,
  `GigabitEthernet0/15`) are accepted and normalised to `0/15` for every
  switch-port parameter, before the protected and caution port checks.

### Fixed

- A call cut off by the caller's request timeout kept the SSH session
  lock; later calls queued behind it and timed out as well, also after
  `wake_server` (retest 0.3.1: `show users`, then `show privilege` and
  `show clock`). The lock wait is bounded. A session that ends in a
  timeout is aborted (Ctrl-C, pager quit, output drained), logged out
  with `exit` within `SWITCH_LOGOUT_TIMEOUT`, then the transport is
  closed hard; it is never reused.
- A failed connect could leave an authenticated SSH transport open for
  the life of the process (netmiko opens the shell channel inside its
  constructor and does not close the transport when that fails). The
  connection is now opened in two steps and always closed on failure.
- Every tool call opened a new SSH login; together with the leak above
  and calls queued behind a hung call this could exhaust the switch's
  SSH sessions after the 0.3.1 retest.
- `config_read("running")` ran into the caller's request timeout twice
  (retest 0.3.1); see `SWITCH_CONFIG_DUMP_TIMEOUT` above.
- PoE parser: `admin` and `auto_class` were always null on the LGS328PC.
  `admin` now comes from the `State` column, `auto_class` from the Power
  Limit Type.
- Allowlist (`examples/commands.yml`): `show priority-map in-priority-type`
  and `show system fan` answered `% Incomplete command.` on the LGS328PC
  (retest 0.3.1). Now `show priority-map in-priority-type vlanPri` and
  `show priority-map in-priority-type ipDscp` (Linksys LGSxxx CLI User
  Manual, QoS) and `show system fan status`; `health_summary` reads the
  fan status with `show system fan status`.

## [0.3.1] - 2026-11-26

Fixes from the first live check of 0.3.0 (LGS328PC, firmware 1.01.02.02,
read tools only). The write checks are still open.

### Fixed

- Config reads use `show current running-config`; the LGS has no show
  command for the startup-config. `config_read("startup")` and
  `config_backup("startup")` answer `Not available:` without sending
  anything. The pre-write snapshot works again with
  `SWITCH_PRE_WRITE_SNAPSHOT=required`.
- `save_config` no longer needs the startup-config: a real save stores
  the masked running-config it saves (tag `pre-save`) and returns the diff
  to the previous save copy; the dry run diffs that copy against the
  current running-config. `config_diff` uses the same baseline.
- PoE parser: Port column `1`–`24`; multi-word columns (`Power Limit
  Type`, `Auto Class`, `Max Power(W)`) no longer leak into power, class or
  device. New fields `max_power_w`, `auto_class`, `limit_type`.
- VLAN parser: `show vlan` key/value blocks (`Vlan ID`, `Member Ports`,
  `Untagged Ports`, wrapped lines, port-channels); `port_status` reports a
  parse warning when nothing is recognised.
- `show_help`: help lines such as `snmp   SNMP information` are no longer
  hidden as `[REDACTED-LINE]`; help lines with a sensitive word are still
  redacted.
- Tool calls that never return (hub timeout, MCP error `-32001`, server
  restart) are now visible in the audit log: each call writes a start line;
  `audit_tail` lists calls without a result as `unfinished`. Result lines
  carry `call_id` and `duration_ms`; an unexpected exception is audited.

### Changed

- `port_set_description` refuses protected ports (fail-closed) and needs
  `confirm_caution_port=true` on caution ports (new parameter).
- The descriptions of the port write tools and the server instructions
  name the configured protected and caution ports (from the environment).
- `examples/commands.yml`: `show monitor all` / `show monitor session *`
  instead of `show monitor` and `show monitor *`; `show priority-map
  in-priority-type` instead of `show priority-map`; `show version` is
  denied (invalid on the LGS); new `show device temperature`, `show system
  fan`, `show system utilization`.
- `health_summary` adds `environment` (temperature, fan, utilization)
  when those shows are allow-listed.
- `mac_table` adds `count_note` when the listing and `show
  mac-address-table count` disagree (live: 54 listed, 85 counted; the
  listing is complete).

## [0.3.0] - 2026-11-26

Not live-tested yet; see "Live test 0.3.0" in the README.

### Changed (breaking)

- `port_set_admin_state` and `poe_set` are replaced by `port_enable`,
  `port_disable`, `poe_enable` and `poe_disable` (same CLI commands), so
  the hub can lock the disabling direction per tool.
- Every write tool defaults to `dry_run=true` and sends nothing unless
  called with `dry_run=false`: the new tools, `port_set_description`,
  `save_config` and the five SNMP tools. Write results are JSON.
- `save_config(dry_run=false)` backs up the current startup-config
  (masked) before `save`, returns the diff of the old and new
  startup-config and the `Config Save Status`. The dry run returns the
  diff startup → running.
- Device text is redacted fail-closed line by line (new `redaction`
  module) in tool output, config error text, config backups and the
  session log: foreign SNMP communities and security names, SNMPv3
  auth/priv keys, `username … password …`, RADIUS/TACACS keys, PEM blocks
  and key blobs. Unrecognised lines with `password|key|secret|community|
  auth|priv` become `[REDACTED-LINE]`. `show radius server` keeps only
  `Label : value` lines. Shows that were shown unmasked before (e.g. a
  foreign community in `show system information`) are now masked.

### Added

- Write pipeline (`writes`): current state, masked running-config
  snapshot (`SWITCH_PRE_WRITE_SNAPSHOT=required|best-effort|off`), send
  with `%` as error pattern, read-back and before/after diff, all in one
  session.
- Read tools with JSON output: `health_summary`, `port_status`,
  `port_counters`, `counters_delta` (baseline in `SWITCH_STATE_DIR`),
  `mac_table`, `lldp_neighbors`, `poe_status`.
- Config tools: `config_read`, `config_backup` (files in
  `SWITCH_BACKUP_DIR`, SHA256, diff to the previous backup),
  `config_diff` (running vs startup, Config Save Status).
- `audit_tail(n=50)` and `show_help(prefix)` (types `show <prefix> ?`,
  clears the line with Ctrl-U, executes nothing).
- Write tools: `port_security_set`, `storm_control_set`,
  `rate_limit_set`, `poe_cycle` (PoE back on in `finally`, retry in a new
  session), `cable_diag`, `syslog_set` (targets only from
  `SWITCH_SYSLOG_ALLOWED`), `mgmt_services_set` (no SSH change, no Telnet
  on; HTTP off only after HTTPS reads back Enabled), `clear_counters`
  (resets the `counters_delta` baseline), `system_identity_set`.
- Protected ports are refused by every new port write tool in every
  direction (fail-closed). New `SWITCH_CAUTION_PORTS`: port writes there
  need `confirm_caution_port=true`, which is audited.
- `examples/commands.yml`: read-only entries for logging-server,
  security-suite, access-lists, port-isolation, monitor, DNS, clock
  properties, dot1x, `show radius server`, RMON, QoS, IGMP/MLD snooping,
  voice VLAN, IPv6 interface/route, `show cli`, `show history`, HTTPS
  status. Running/startup config and cable diagnostics stay denied for
  `show`.
- README: unlock-class proposal, new environment variables, live-test
  checklist for 0.3.0.

### Not included

- Port mirroring (no guaranteed automatic removal), management ACL,
  TFTP export, environment/SFP values (need `show_help` findings first),
  speed/duplex. See the README for the reasons.

### Fixed

- Idle-timeout errors from `send_paged` now run the last output line through
  `redact_show_output`, and omit that line entirely for sensitive SNMP show
  commands (`show snmp community|viewtree|user` and abbreviated forms such
  as `sh snmp comm`) so a foreign community cannot leak to the MCP client
  ([#5](https://github.com/WackEarl/lgs-switch-mcp/issues/5)).
- `_is_snmp_sensitive_show` and `redact_show_output` recognize those
  abbreviated forms with the same whitespace normalization as the show-tool
  command filter and prefix matching on `show` and the kind word, so the
  session log stays off and community listings stay masked
  ([#5](https://github.com/WackEarl/lgs-switch-mcp/issues/5)).
- `save_config` no longer waits silently on a Y/N confirmation. If the
  last visible line after `save` ends in `(y/n)`, `[Y/N]`, or `(yes/no)`
  (optionally followed by `:` or `?`), it answers `y` once. A second
  confirmation is not answered and fails. Any other prompt is not
  answered (fail-closed): after `SWITCH_READ_TIMEOUT` seconds without new
  output the error says `save did not complete` and that whether
  startup-config was written is unknown, and includes the last line.
  `show` and read-backs never answer a confirmation. The LGS328PC save
  prompt text is not live-confirmed; keep `save_config` gated in the hub
  until it is
  ([#4](https://github.com/WackEarl/lgs-switch-mcp/issues/4)).

### Changed

- `connection.py` is split into `errors.py` (`SwitchConnectionError`),
  `parser.py` (pager and output cleanup), and `commands.py` (CLI
  sequence builders). The session/transport layer stays in
  `connection.py`, which still re-exports the previous public names.
  The old `ConnectionError` name remains as an alias. MCP tool names,
  parameters, and return values are unchanged
  ([#6](https://github.com/WackEarl/lgs-switch-mcp/issues/6)).
- `port_overview` runs its four allow-listed show commands in a single SSH
  session (same process-wide lock, same command filter, no config sent)
  instead of opening one session per command. If a command fails inside
  the session, the remaining commands are not sent (the channel state is
  unknown) and are listed under `errors` as not run; output collected
  before the failure is still returned. A connect failure is reported once
  per command after a single connection attempt
  ([#5](https://github.com/WackEarl/lgs-switch-mcp/issues/5)).

## [0.2.0] - 2026-11-13

### Added

- Narrow, unlock-gated SNMP tools to create an allow-listed IF-MIB view,
  bind a non-default v2c community from `SWITCH_SNMP_COMMUNITY` (never a
  tool argument; redacted as `[REDACTED]`), remove only `public`/`private`
  after the new community is verified with a restricted view, and remove
  only `noAuthUser`. POWER-ETHERNET-MIB (`1.3.6.1.2.1.105`) is an
  allow-listed read-view subtree so HA can read PoE. Command templates live in `snmp_cli.py`
  and follow the Linksys LGSXXX CLI manual
  ([#7](https://github.com/WackEarl/lgs-switch-mcp/issues/7)).
  The write-view create syntax and the viewtree read-back were
  live-confirmed on 2026-11-13; community create/remove syntax and the
  SNMP read/write path through an external client are not.
  SNMP write tools require `SWITCH_SNMP_WRITE_ENABLED=1` (off by default),
  disable the session log for the call, and redact community echoes
  (including wrapped lines and `re.escape`/`repr` variants). The community
  charset is `[A-Za-z0-9_]`, length 8–32.
- `snmp_write_view_create(view_name, subtree)` builds a separate write
  view from the writable columns only: `ifAdminStatus`
  (`1.3.6.1.2.1.2.2.1.7`), `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`) and
  `pethPsePortAdminEnable` (`1.3.6.1.2.1.105.1.1.1.3`) for PoE on/off
  from Home Assistant (Vikunja task 48). Whole MIB subtrees are refused.
  It sends one `snmp view <view> <column> included` line with
  `error_pattern="%"`, verifies it in `show snmp viewtree`, and on any
  failure removes the column again and checks that the viewtree equals
  the state before (else `ROLLBACK NOT VERIFIED`). There are no per-port
  exclusions: the protected ports (`SWITCH_PROTECTED_PORTS`, production
  0/10 and 0/24) are refused by the tools only, not at SNMP level
  (owner decision, 2026-11-13). Anyone with the write community can switch them
  directly over SNMP; the README says so. 0/15 (EoC converter feeding the
  Zigbee router) is documented as "do not turn PoE off", not locked.
- The `show snmp viewtree` parser reads the layout from the network admin's read-only
  check (`Subtree OID  : 1` / `Subtree Mask : 1` / `View Type    :
  Included`) and starts a new entry at every `View Name` line, so blank
  line separated blocks work too. Masks are read per RFC 3415: a full
  mask such as `1`, `1.1.1` or `ff:e0` (11-arc column) is exact, a mask
  with a 0 inside the OID length is a wildcard and refused. The 0.2.0
  live check printed a column mask as `1.1.1…` (one `1` per arc) with
  Storage Type Non-volatile.

### Changed

- `snmp_community_create(view_name, access, write_view=None)`: `rw` now
  requires a separate `write_view` (`snmp access … read <ReadView> write
  <WriteView> notify none`); the same view for read and write is refused,
  and `ro` refuses a `write_view`. The write view is checked strictly
  before sending, and after sending the access entry must name exactly
  the requested views.
- The `show snmp viewtree` read-back now verifies write views strictly
  (explicit included/excluded type, exact mask, only write-allowed
  columns) in `snmp_community_create` and `snmp_community_remove`. Read and
  write views with an unrecognised (possibly wildcard) mask are refused.
- `snmp_view_create` refuses any subtree for a view that is used as a
  write view or holds a writable column or an excluded entry (whole MIBs would
  widen the column-only write view), and now runs in a
  single session with the "Configuration was sent, verification failed"
  wrapper for post-send read-back errors.
- README: install pins now point to `@v0.2.0`.

### Live test

The network admin's 0.2.0 live check on an LGS328PC (firmware 1.01.02.02, commit
177dc84, 2026-11-13):

- Device error lines start with `%` (example: `% Invalid input detected
  at '^' marker`).
- A column OID without a mask is accepted (`snmp view <view> <column>
  included`).
- `show snmp viewtree` (and its alias `show snmp view`) prints a column
  entry as `Subtree OID  : 1.3.6.1.2.1.105.1.1.1.3` / `Subtree Mask :
  1.1.1.1.1.1.1.1.1.1.1` (one `1` per arc), `View Type : Included`,
  `Storage Type : Non-volatile` immediately, without `save_config`.
- `port_set_admin_state` and `poe_set` (CLI) worked on a free port
  (0/18) and were reversed.

Not live-verified in that check:

- The SNMP read/write path through an external client (GET/WALK/SET).
- Community create/remove syntax (the switch lists communities under a
  Community Index, so the ISS form with `index` may be required; the
  Linksys form without `index` remains unconfirmed).
- `no snmp view <view> <oid>` to remove a single entry (the rollback
  path was not triggered).

### Security

- Removed again before release (owner decision, 2026-11-13): the view-level
  exclusions of the protected ports, `SWITCH_SNMP_PROTECTED_IFINDEXES`,
  `SWITCH_SNMP_PROTECTED_POE_INDEXES` and the two-stage
  exclusion/include apply with its staged rollback. They needed live
  ifIndex and PoE index mappings that the tools cannot read. What stays:
  the tool-level port lock, `error_pattern="%"`, read-back verification
  with rollback of the added column, the central OID normalization and
  `SWITCH_SNMP_WRITE_ENABLED` off by default.
- `oid_arcs` accepts a leading `iso` only as `iso.3…`; `iso.1.3.6…`, a
  bare `iso` and other variants are refused (fail-closed) instead of
  being read as `1.1.3.6…`.
- One central OID normalization (`oid_arcs`/`canonical_oid`/`oid_within`)
  for all view checks, prechecks and read-backs: leading dot, `iso`,
  trailing dots and whitespace are accepted, prefixes are compared by
  whole arcs, and unknown formats or partial (wildcard) masks are refused,
  also in the read-view precheck. Before, other OID spellings could hide
  a write view from `snmp_view_create`, so the whole POWER-ETHERNET-MIB
  could be added to it (found in review). The read-view precheck now refuses any
  view with excluded entries or writable columns.
- SNMP view names are compared exactly (case-sensitive) in all view
  checks (`view_is_restricted`, `view_is_write_safe`, the read-back
  checks, and the PoE/write-view prechecks). A view name that differs
  from an existing view only in letter case is refused (fail-closed),
  because it is not live-confirmed whether ISS treats view names
  case-sensitively (found in review). `snmp_view_create` now reads `show snmp viewtree` before
  sending and refuses if it cannot be parsed.

- SNMP community rejection paths return only a generic message (no device
  text). ANSI and prompt redraws are stripped only inside
  `snmp community name` … `security` command spans; other output stays
  byte-identical except for secret replacements. Read-back
  failures after a config send are always reported as "Configuration was
  sent, verification failed". The `show` tool disables the session log for
  `show snmp community` / `viewtree` / `user`, and session-log Community
  Name fields are masked by label. The extra terminal-width helper was
  removed; `cisco_s300` already sends `terminal width 511` in
  `session_preparation`.

## [0.1.3] - 2026-11-13

Fixes from the architecture review and the remaining nits from the
0.1.2 live retest, tracked in [#2](https://github.com/WackEarl/lgs-switch-mcp/issues/2)
and [#3](https://github.com/WackEarl/lgs-switch-mcp/issues/3).

### Fixed

- `config_output_is_error` classifies device output after ANSI/control
  stripping (same helper as the output cleanup, including the
  terminated-OSC rule). A line is a failure if it contains `%` anywhere
  (including a same-line prompt such as
  `LGS328PC(config-if)#% Invalid input`), or if after removing a leading
  prompt the remainder is not empty, is not one of the commands just
  sent, and contains the word `Error` or `Invalid` (case-insensitive).
  Echoed descriptions such as `description "Error LED"` are therefore
  not reported as rejected, including an unquoted echo
  (`description Error LED`); a separate line like
  `Error: port is protected` is
  ([#3](https://github.com/WackEarl/lgs-switch-mcp/issues/3)).
- `port_set_description` now reads back via `show interfaces description`
  and parses the row for the port (the previous
  `show interfaces gigabitethernet 0/N` read-back does not show
  descriptions on the LGS). Port rows `Gi0/7`, `gi7`, `gi1/0/7`, and
  `GigabitEthernet0/7` are recognised (and `0/1` does not match `0/10`).
  With a `Description`/`Name` header, the note compares the column
  (whitespace collapsed). A strict prefix is reported as probably
  truncated only if it is at least 8 characters, or if a known column
  width (next header column, or the Description bar on a separator
  line) equals the parsed length; a stale short prefix such as `Rep`
  is a mismatch. Without a recognised header, a row that
  ends with the expected text is verified; otherwise the note says
  `could not verify (unknown table layout)` and includes the raw row.
  A missing row is `could not verify (port row not found)` plus a short
  preview, never a mismatch. Leading or trailing spaces in the
  description are rejected
  ([#2](https://github.com/WackEarl/lgs-switch-mcp/issues/2)).
- Blank lines immediately before a page break (as well as after it) are
  dropped, so the two leftover blank lines seen at page breaks in the
  v0.1.2 live retest are removed ([#2](https://github.com/WackEarl/lgs-switch-mcp/issues/2)).
- `examples/commands.yml` lists `show interfaces description` (already
  covered by `show interfaces *`).

### Changed

- README: install pins now point to `@v0.1.3`.

## [0.1.2] - 2026-11-12

Fixes from the 0.1.1 live retest on the LGS328PC (firmware 1.01.02.02),
tracked in [#1](https://github.com/WackEarl/lgs-switch-mcp/issues/1).

### Fixed

- `port_set_description` now sends the text quoted (`description "Repeater EG"`).
  Unquoted, the LGS CLI rejected multi-word descriptions with
  `% Invalid input detected` at the second word. Quoting is always applied;
  input validation still forbids quotes (#1).
- Page breaks no longer leave an ESC byte and blank lines in the output (for
  example between `Gi0/20` and `Gi0/21`). Stray ESC bytes, wider ANSI/VT100
  sequences (CSI, OSC, charset, two-byte ESC), and other control characters
  are stripped; blank lines directly after a page break are dropped, other
  blank lines are kept (#1).

- Descriptions consisting only of spaces are rejected.

### Known limitations

- If netmiko splits an escape sequence across two reads, the orphaned ESC can
  still take a following character with it (e.g. `ESC D…`, `ESC [G…`). An OSC
  sequence is only stripped when terminated (BEL or ST), so an orphaned
  `ESC ]` no longer eats the rest of the line.

### Added

- `port_set_description` appends an informational read-back check: whether
  the description shows up in `show interfaces gigabitethernet 0/N` without
  quotes, with quotes (stored literally), or not at all.

### Changed

- README: read-back `show interfaces gigabitethernet 0/N` and the pager loop
  are confirmed live; install pins now point to `@v0.1.2`.

## [0.1.1] - 2026-11-12

Fixes from the first live test on an LGS328PC (firmware 1.01.02.02).

### Fixed

- Long `show` outputs (`show interfaces`, `show interfaces status`,
  `show power inline`, `show spanning-tree`, `show mac-address-table`, and the
  `show interfaces gigabitethernet 0/N` read-back) no longer fail with
  `Pattern not detected`. Exec commands now run through a pager-aware read
  loop that answers `--More--`-style prompts with a space, waits for the real
  prompt, and strips pager text, backspaces, and ANSI sequences. Read-backs
  and `save` use the same loop.
- An unwritable audit log (for example `OSError: [Errno 30] Read-only file
  system`) no longer aborts the tool. The failure is written to stderr and
  appended to the tool result as an `audit_warning:` line.

### Added

- Best-effort paging-off at session start: `configure terminal`,
  `set cli pagination off`, `end`. On this ISS-based CLI the command only
  exists in Global Configuration mode; if it is rejected, the pager loop still
  handles paging. Disable with `SWITCH_PAGING_OFF=0`.
- `SWITCH_READ_TIMEOUT` (default 60 s, 1–600): idle timeout of the read loop
  and netmiko `read_timeout_override`.
- `SWITCH_SESSION_LOG`: optional netmiko session log (append, mode 0600,
  password masked by netmiko's `no_log`, writes not recorded). An unwritable
  path disables the log with a warning.
- Startup check: warns on stderr when `SWITCH_AUDIT_LOG` is unset or not
  writable, when `SWITCH_READ_TIMEOUT` is invalid, or when `SWITCH_SESSION_LOG`
  is not writable. Startup never aborts and never contacts the switch.

### Changed

- `examples/commands.yml`: removed `show version` (invalid on this firmware);
  use `show system information`.
- README example audit path is now `/data/netmiko/switch-audit.log`.

## [0.1.0] - 2026-11-12

### Added

- Initial stdio MCP wrapper `netmiko-mcp-linksys` for Linksys LGS-series
  switches, based on netmiko 4.8.0 and netmiko-mcp 0.3.0 (command filter reused),
  with paramiko 4.0.0 and mcp 2.3.0.
- Tools: `show`, `port_overview` (read-only), `port_set_admin_state`,
  `poe_set`, `port_set_description`, and `save_config`. No VLAN, reboot, or
  reset tools.
- Hard parameter validation for ports (`0/1`–`0/28`), PoE range (`0/1`–`0/24`),
  interface descriptions (`^[A-Za-z0-9 ._-]{1,32}$`), and protected ports,
  applied before any SSH connection is opened.
- Protected ports fail closed: if `SWITCH_PROTECTED_PORTS` is unset, empty, or
  invalid, disable and PoE-off are refused on every port.
- Command whitelist/deny list for `show` via `netmiko_mcp.security.validate_command`
  and `NETMIKO_MCP_COMMAND_FILE`. The wrapper also rejects `|`, `;`, and
  newlines (deny wins).
- JSON-lines audit log (`SWITCH_AUDIT_LOG`) with mode 0600; passwords are
  redacted from parameters and results.
- One SSH session per tool call, serialized by a process-wide lock. No
  connection at process start. No automatic save.
- Host-key pinning through `SWITCH_KNOWN_HOSTS` (`ssh_strict=True`,
  `use_keys=False`, `allow_agent=False`, system host keys disabled).
