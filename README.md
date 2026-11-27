# lgs-switch-mcp

[![CI](https://github.com/WackEarl/lgs-switch-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/WackEarl/lgs-switch-mcp/actions/workflows/ci.yml)

stdio MCP server for a single Linksys LGS-series switch (developed against the
LGS328PC CLI). Previously published as `netmiko-mcp-linksys`. The GitHub
repository is [WackEarl/lgs-switch-mcp](https://github.com/WackEarl/lgs-switch-mcp)
(the previous path redirects).

This project is a separate wrapper, based on [netmiko](https://github.com/ktbyers/netmiko)
and [netmiko-mcp](https://github.com/ktbyers/netmiko_mcp) by Kirk Byers. The `show`
tool reuses netmiko-mcp's command filter (`netmiko_mcp.security.validate_command`)
and the same allow/deny list format (`commands.yml`). Configuration tools send
only fixed command sequences built by this wrapper; the model never supplies
free-form config. See [Credits](#credits).

**This is 0.4.0**, the rename to `lgs-switch-mcp` (package and GitHub
repository), GitHub Actions CI, and upstream credits. The 0.3.2 session
handling is included (see [What is new in 0.3.2](#what-is-new-in-032)).
0.3.1 fixed the first live check of 0.3.0 (see
[What is new in 0.3.1](#what-is-new-in-031)). 0.3.0 added parsed JSON read tools (`health_summary`,
`port_status`, `port_counters`, `counters_delta`, `mac_table`,
`lldp_neighbors`, `poe_status`), masked config reads and backups
(`config_read`, `config_backup`, `config_diff`), `audit_tail`,
`show_help`, and narrow write tools (port security, storm control, rate
limit, PoE cycle, cable diagnostics, syslog target, management services,
clear counters, system identity). Every write tool defaults to
`dry_run=true`, takes a masked running-config snapshot before a real
write, checks device output for `%` and returns a before/after diff.
Device text is redacted fail-closed, line by line. Protected ports are
refused by every new port write tool; caution ports need an explicit
confirmation. See [What is new in 0.3.0](#what-is-new-in-030) and
[Retest 0.3.2](#retest-032-network-admin).

0.2.0 added the unlock-gated SNMP tools; 0.1.x was live-tested on an
LGS328PC with firmware 1.01.02.02 (SSH with `ssh-rsa` via paramiko 4.0.0;
login lands directly in privilege 15 with prompt `LGS328PC#`; no banner or
second login prompt). See [Live-test status](#live-test-status).

## Install and run

The intended way to run this server is the packaged entrypoint, pinned to a
tag:

```bash
uvx --from git+https://github.com/WackEarl/lgs-switch-mcp@v0.4.0 lgs-switch-mcp
```

From a local checkout:

```bash
uvx --from /path/to/lgs-switch-mcp lgs-switch-mcp
```

The previous command name `netmiko-mcp-linksys` still works and prints a
deprecation warning.

The process speaks MCP over stdio. It does **not** open an SSH session at
startup; a connection is made only when a tool is called.

`paramiko==4.0.0` is intentional. The target switch speaks `ssh-rsa` with
SHA-1; paramiko 5.x rejects that host-key algorithm.

A compatibility shim, `lgs_mcp.py`, exists only for the older hub invocation
`python /config/netmiko/lgs_mcp.py`. That file is not a standalone
implementation: it imports `lgs_switch_mcp` (the previous
`netmiko_mcp_linksys` import still works as a deprecated alias). Prefer the
`uvx --from ... lgs-switch-mcp` entry above. If you must keep the old
command, add `--with git+https://github.com/WackEarl/lgs-switch-mcp@v0.4.0`
so the package is installed in that environment.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `SWITCH_HOST` | yes (at tool call) | Switch IP or hostname. |
| `SWITCH_USER` | yes (at tool call) | SSH username. |
| `SWITCH_PASSWORD` | yes (at tool call) | SSH password. Never logged or returned. |
| `SWITCH_SNMP_COMMUNITY` | yes before `snmp_community_create` / `snmp_community_remove` | SNMPv2c community string for the new, non-default community. Never a tool argument, never logged or returned (shown as `[REDACTED]`). Must not be `public` or `private`; 8–32 characters from `[A-Za-z0-9_]` (no dots or dashes). An invalid value is not used for redaction. |
| `SWITCH_SNMP_WRITE_ENABLED` | yes (`1`) before any SNMP write tool | Hard gate, **off by default**. SNMP write tools refuse unless this is exactly `1`. Leave it unset until the remaining unconfirmed CLI (community create/remove) has been verified live. |
| `SWITCH_DEVICE_TYPE` | no | netmiko device type. Default: `cisco_s300`. |
| `SWITCH_KNOWN_HOSTS` | yes (at tool call) | Path to an OpenSSH `known_hosts` file with the switch host key. System host keys are not used. |
| `SWITCH_PROTECTED_PORTS` | yes before any port write | Comma-separated ports (e.g. `0/10,0/24`). `port_disable` and `poe_disable` refuse them; every other port write tool except `port_enable` and `poe_enable` refuses them in every direction (`port_set_description`, `port_security_set`, `storm_control_set`, `rate_limit_set`, `poe_cycle`, `cable_diag`, `clear_counters(port)`). The configured list is shown in the descriptions of the port write tools. If this variable is unset, empty, or contains an invalid port, those tools fail closed (every port is refused). |
| `SWITCH_CAUTION_PORTS` | no | Comma-separated ports (e.g. `0/15`) where every port write tool needs `confirm_caution_port=true`. The flag is recorded in the audit log; the list is shown in the tool descriptions. Unset means no caution ports; an invalid entry refuses all port writes (fail-closed). |
| `SWITCH_SYSLOG_ALLOWED` | yes before `syslog_set` | Comma-separated IPv4 addresses that `syslog_set` may configure as a syslog target. There is no free value: unset, empty, or invalid refuses `syslog_set`. |
| `SWITCH_BACKUP_DIR` | no | Directory for masked config backups and pre-write snapshots. Default `/data/netmiko/backups` (created with mode `0700`, files `0600`). |
| `SWITCH_STATE_DIR` | no | Directory for small state files (`counters_delta` baseline). Default `/data/netmiko/state`. |
| `SWITCH_PRE_WRITE_SNAPSHOT` | no | `required` (default): a real write first stores a masked running-config snapshot and is refused if that fails. `best-effort`: write anyway and report the failure. `off`: no snapshot. `save_config` stores the masked running-config it saves under the same rule (the LGS cannot show its startup-config). |
| `NETMIKO_MCP_COMMAND_FILE` | yes for `show`, `port_overview` and the parsed read tools | Path to a `commands.yml` allow/deny list. See `examples/commands.yml`. Restart the server after edits (`lru_cache`). |
| `SWITCH_AUDIT_LOG` | no (recommended) | If set, append JSON lines per tool call: a `"phase": "start"` line with a `call_id` before the tool runs, and the result line with the same `call_id` and `duration_ms`. A start line without a result marks a call that was cut off (hub timeout such as MCP error `-32001`, server restart); `audit_tail` lists it as `unfinished`. The file is created with mode `0600`. Passwords are redacted from parameters and results. There is no default path; unset means no audit (warned at startup). An unwritable path does not break tools: a warning goes to stderr and the result gets an `audit_warning:` line. |
| `SWITCH_READ_TIMEOUT` | no | Seconds without new output before a command is given up. Also passed to netmiko as `read_timeout_override` (cut to the call budget left). Default `60`, range `1`–`600`. |
| `SWITCH_CALL_BUDGET` | no | Wall-clock seconds one tool call may spend on the switch: waiting for the session lock, connecting and every command. Default `45`, range `5`–`600`. When it runs out the call ends with a tool error; the SSH session is aborted (Ctrl-C), logged out and closed, and the reconnect cooldown starts (`SWITCH_COOLDOWN_BASE`). Keep it about 15 s below the caller's request timeout: MCP clients give up after 60 s by default (MCP error `-32001`); the hub's own `MCP_CALL_TIMEOUT_MS` defaults to 300 s. Applying writes (`dry_run=false`) are not cut by it (a write must not stop between sending and its read-back); they still wait at most one budget for the session lock. |
| `SWITCH_SESSION_IDLE` | no | Seconds a clean SSH session is kept open for the next call, then logged out with `exit`. Default `10`, range `0`–`300`; `0` logs out after every call. There is never more than one SSH session to the switch (tool calls and the background config dump share it). |
| `SWITCH_LOGOUT_TIMEOUT` | no | Seconds the switch gets to close the channel after `exit`; after that the transport is closed hard. Default `3`, range `0.5`–`30`. |
| `SWITCH_COOLDOWN_BASE` | no | Reconnect protection. After a command timeout or a failed or slow connect, no new SSH connection is opened for this many seconds; the call answers `Switch cooling down …; retry in Ns` at once. The cooldown doubles with every further failure in a row and resets after a successful call. Stored in `SWITCH_STATE_DIR/ssh-breaker.json`, so a server restart keeps it. Default `30`, range `0`–`3600`; `0` turns it off. Nothing retries automatically. |
| `SWITCH_COOLDOWN_MAX` | no | Ceiling of the doubling cooldown. Default `600`, range `1`–`86400`. |
| `SWITCH_CONFIG_DUMP_TIMEOUT` | no | Limit in seconds for one background running-config dump (`config_read`, `config_backup`, `config_diff`). Default `240`, range `30`–`600`. See `config_read`. |
| `SWITCH_PAGING_OFF` | no | `1` (default) sends `configure terminal` / `set cli pagination off` / `end` at session start, best effort. `0` skips it; the pager loop handles paging either way. |
| `SWITCH_SESSION_LOG` | no | Debug only. If set, netmiko appends a session log there (mode `0600`). netmiko masks the password (`no_log`) and only channel reads are recorded. The log does contain full show output (MAC/ARP tables, descriptions); unset it after debugging. An unwritable path disables the log with a warning. |

Python 3.12 or newer is required.

## mcp-hub entry snippet

Secrets stay in hub template variables. Write tools are gated by the hub
`unlock` feature (0.12+); `maxMinutes: 0` means every call needs a fresh
approval. See [Unlock classes](#unlock-classes-proposal) for the
proposed per-tool classes; the snippet below gates every write tool with
`maxMinutes: 0`, which is the safe default for a hub that supports only
one unlock block per server. Keep `SWITCH_SNMP_WRITE_ENABLED` unset (the tools refuse)
until the community-create syntax has been confirmed live; only then set it to `1` in the
hub env (shown below as the value to use after that confirmation). Fill `SWITCH_PROTECTED_PORTS` after the first read test —
until it is set to a valid list, disable and PoE-off are refused.

The snippet below is the current production pin (`@v0.4.0` and the new
command name). The previous command `netmiko-mcp-linksys` remains a
deprecated alias.

```json
{
  "switch": {
    "command": "uvx",
    "args": [
      "--python", "3.12",
      "--from", "git+https://github.com/WackEarl/lgs-switch-mcp@v0.4.0",
      "lgs-switch-mcp"
    ],
    "env": {
      "SWITCH_HOST": "192.0.2.10",
      "SWITCH_USER": "${SWITCH_USER}",
      "SWITCH_PASSWORD": "${SWITCH_PASSWORD}",
      "SWITCH_SNMP_COMMUNITY": "${SWITCH_SNMP_COMMUNITY}",
      "SWITCH_SNMP_WRITE_ENABLED": "1",
      "SWITCH_DEVICE_TYPE": "cisco_s300",
      "SWITCH_KNOWN_HOSTS": "/config/netmiko/known_hosts",
      "SWITCH_PROTECTED_PORTS": "<uplink and management ports, e.g. 0/24>",
      "SWITCH_CAUTION_PORTS": "<ports that need confirm_caution_port, e.g. 0/15>",
      "SWITCH_SYSLOG_ALLOWED": "<syslog receiver IPv4, e.g. 192.0.2.20>",
      "SWITCH_BACKUP_DIR": "/data/netmiko/backups",
      "SWITCH_STATE_DIR": "/data/netmiko/state",
      "SWITCH_PRE_WRITE_SNAPSHOT": "required",
      "NETMIKO_MCP_COMMAND_FILE": "/config/netmiko/commands.yml",
      "SWITCH_AUDIT_LOG": "/data/netmiko/switch-audit.log",
      "SWITCH_READ_TIMEOUT": "60",
      "SWITCH_CALL_BUDGET": "45",
      "SWITCH_SESSION_IDLE": "10",
      "SWITCH_LOGOUT_TIMEOUT": "3",
      "SWITCH_COOLDOWN_BASE": "30",
      "SWITCH_COOLDOWN_MAX": "600",
      "UV_CACHE_DIR": "/data/uv-cache",
      "UV_PYTHON_INSTALL_DIR": "/data/uv-python",
      "UV_TOOL_DIR": "/data/uv-tools",
      "PATH": "/usr/local/bin:/usr/bin:/bin",
      "HOME": "/home/node"
    },
    "unlock": {
      "tools": [
        "save_config",
        "mgmt_services_set",
        "snmp_view_create",
        "snmp_write_view_create",
        "snmp_community_create",
        "snmp_community_remove",
        "snmp_user_remove",
        "port_disable",
        "poe_disable",
        "poe_cycle",
        "port_security_set",
        "storm_control_set",
        "rate_limit_set",
        "cable_diag",
        "syslog_set",
        "clear_counters",
        "system_identity_set"
      ],
      "maxMinutes": 0
    }
  }
}
```

Paths under `/config` are read-only inside the hub container; put the audit
log, the backup and state directories (and an optional
`SWITCH_SESSION_LOG`) under `/data`.

Free (not gated): `show`, `port_overview`, all parsed read tools,
`config_read`, `config_backup`, `config_diff`, `audit_tail`, `show_help`,
`port_set_description`, `port_enable`, `poe_enable`.

### Unlock classes (proposal)

The hub locks per tool, not per parameter; that is why 0.3.0 splits
`port_set_admin_state` / `poe_set` into enable and disable tools. Proposed
classes for the hub entry (needs a hub that supports more than one
unlock block per server; until then use `maxMinutes: 0` for all):

| Class | Tools |
| --- | --- |
| Free | all read tools except `cable_diag`; `port_set_description`, `port_enable`, `poe_enable` |
| Unlock, short slot (about 15 minutes) | `syslog_set`, `port_security_set`, `storm_control_set`, `poe_cycle`, `cable_diag`, `clear_counters`, `system_identity_set`, `rate_limit_set`, `port_disable`, `poe_disable` |
| Unlock, `maxMinutes: 0` (every call) | `save_config`, `mgmt_services_set`, the five SNMP tools |

A dry run of a gated tool also needs the unlock, because the hub cannot
see the `dry_run` parameter. That is intended: the dry run reads the
device.

Copy `examples/commands.yml` to `NETMIKO_MCP_COMMAND_FILE`. Create
`SWITCH_KNOWN_HOSTS` yourself from a verified host key; do not use
`examples/known_hosts` as-is (it is a placeholder, not a real key).

## Tools

| Tool | Effect | Saved? |
| --- | --- | --- |
| `show(command)` | Allow-listed show command via `netmiko_mcp.security.validate_command`, then `send_command`. Pipe, semicolon, and newlines are rejected. Deny wins. | n/a |
| `port_overview()` | Read-only bundle of `show system information`, `show vlan`, `show power inline`, and `show interfaces`, each passed through the same command filter, run in one SSH session. If one command fails, the remaining ones are not sent and are listed as not run. | n/a |
| `port_enable(port, confirm_caution_port=False, dry_run=True)` | `interface gigabitethernet 0/N` then `no shutdown`. Allowed on protected ports. Replaces `port_set_admin_state(enabled=True)`. | no |
| `port_disable(port, confirm_caution_port=False, dry_run=True)` | `interface gigabitethernet 0/N` then `shutdown`. Protected ports refused (fail-closed). Replaces `port_set_admin_state(enabled=False)`. | no |
| `poe_enable(port, …)` / `poe_disable(port, …)` | `power inline enable` / `power inline disable`. PoE ports: `0/1`–`0/24`. `poe_disable` refuses protected ports. Replace `poe_set`. | no |
| `port_set_description(port, text?, confirm_caution_port=False, dry_run=True)` | `description "<text>"` (always quoted, the LGS CLI takes only one word unquoted) or `no description` when `text` is omitted. Protected ports refused (fail-closed), caution ports need `confirm_caution_port=true` (0.3.1). The result includes an informational read-back note (verified, quoted, empty, probably truncated, or could not verify). | no |
| `save_config(dry_run=True)` | The LGS cannot show its startup-config. Dry run: masked diff from the running-config stored at the last save through this server to the current running-config, and the `Config Save Status`. Real: stores the masked running-config that is saved (`SWITCH_BACKUP_DIR`, tag `pre-save`; refused if that fails while `SWITCH_PRE_WRITE_SNAPSHOT=required`), sends privileged exec `save`, returns the diff to the previous save copy and the `Config Save Status`. Gate with hub `unlock`. | yes |
| `snmp_view_create(view_name, subtree)` | Add one **included** subtree from a fixed OID allowlist (`interfaces`, `ifmib`, `power-ethernet`) to a **read** view. Refused for a view that is used as a write view or holds a writable column or an excluded entry. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |
| `snmp_write_view_create(view_name, subtree)` | Add one writable column to a **write** view: `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`), `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`) or `pethPsePortAdminEnable` (`1.3.6.1.2.1.105.1.1.1.3`, PoE on/off). One `snmp view <view> <column> included` line, sent with a `%` error check and verified in `show snmp viewtree`; on failure it is removed again (see below). Whole MIB subtrees are never allowed. **No per-port exclusions:** the column is writable for every port, protected ports included. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Create and viewtree read-back live-confirmed; rollback (`no snmp view`) is not.** | no |
| `snmp_community_create(view_name, access, write_view=None)` | Create a v2c community from `SWITCH_SNMP_COMMUNITY` bound to an existing restricted read view (`view_name`). `ro`: write view `none`. `rw`: requires a separate `write_view` that passes the write-view check (only writable columns). The secret is never a tool argument. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |
| `snmp_community_remove(name)` | Remove `public` or `private` only, and only after the configured community is verified present with a restricted view. Never removes the configured community. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |
| `snmp_user_remove(name)` | Remove `noAuthUser` only. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |

All SNMP tools also take `dry_run=True` (default): the read-only
prechecks run and the commands of the first configuration step are
returned; nothing is sent.

New in 0.3.0, read-only (JSON output, `include_raw=true` adds the
redacted device text where offered):

| Tool | Reads |
| --- | --- |
| `health_summary(log_entries=10)` | One session: `show system information` (uptime, Config Save Status), `show power detail` (budget, consumption), `show power inline` (W per port), `show interfaces status` (up/down, speed, duplex), `show interfaces counters` (only ports with error/discard counters > 0), `show logging` (last entries); `show device temperature`, `show system fan status`, `show system utilization` (0.3.1, `environment`, only if allow-listed; a missing one is named in `environment_skipped`). |
| `port_status()` | Per port: link, speed, duplex, description, VLANs, PoE (W/class/status), LLDP neighbor. |
| `port_counters(port?)` | `show interfaces counters`, all ports or one. |
| `counters_delta(port?)` | Difference since the previous call (baseline in `SWITCH_STATE_DIR`); `new_errors` lists growing error/discard counters. The first call stores the baseline. |
| `mac_table(port?, mac?)` | `show mac-address-table` and `count`, filtered by port or MAC. If the listing (with its own total line) and the count differ, `count_note` says so. |
| `lldp_neighbors()` | `show lldp neighbors`. |
| `poe_status()` | `show power detail` and `show power inline`. On the LGS328PC `admin` is the `State` column and `auto_class` is derived from the Power Limit Type (`Enabled` for `Auto Class`). |
| `config_read(source="running")` | Masked `show current running-config`. `source="startup"` answers `Not available:` (the LGS has no show command for the startup-config). Stays denied for `show`. The dump runs in the background (limit `SWITCH_CONFIG_DUMP_TIMEOUT`): if it is not done within the call budget the answer is `Pending: …`, and the next `config_read`, `config_backup` or `config_diff` within 5 minutes gets the finished dump once (`read_at`, `dump_seconds`, `age_seconds`). A dump from before a configuration change through this server is never handed out. |
| `config_backup(source="running", tag?)` | Stores the masked running-config as `SWITCH_BACKUP_DIR/YYYY-MM-DD_HHMM_running[_tag].cfg`; returns path, SHA256 and the diff to the previous running backup. |
| `config_diff()` | Masked diff from the running-config stored by the last `save_config` through this server (tag `pre-save`) to the current running-config, plus `Config Save Status`. Without such a copy only the status is returned. Saves made elsewhere are not seen. |
| `audit_tail(n=50)` | Last `n` (1–500) audit entries, redacted again on read; finished calls carry `duration_ms`, calls without a result are listed as `unfinished` with `age_ms` since their start. |
| `show_help(prefix="")` | Types `show <prefix> ?`, reads the help listing, clears the line with Ctrl-U. Nothing is executed. `prefix`: up to five words from `[a-z0-9-]`. `keyword  description` help lines without a sensitive word are not treated as config lines (0.3.1); everything else is redacted as usual. |

New in 0.3.0, writes (all `dry_run=True` by default, none saves):

| Tool | CLI (LGS ISS manual) |
| --- | --- |
| `port_security_set(port, limit?, …)` | `port-security <1-256>` / `no port-security` (interface). Read-back `show interface port-security gigabitethernet 0/N`. |
| `storm_control_set(port, storm_type, level_pps?, …)` | `storm-control {broadcast\|unknown-multicast\|dlf} level <pps>` / `no storm-control <type> level`. Read-back: the interface block of the masked running-config. |
| `rate_limit_set(port, direction, kbps?, …)` | `rate-limit {input\|output} <1-80000000>` / `no rate-limit <direction>`. Read-back: interface block. |
| `poe_cycle(port, off_seconds=5, …)` | `power inline disable`, wait 2–60 s, `power inline enable`, in one session. PoE is switched on again in a `finally`, with one retry in a new session; if both fail the result says the port may be left disabled. |
| `cable_diag(port, …)` | `show interface cable-diag gigabitethernet 0/N` (stays denied for `show`). Active test: may drop the link for a few seconds. |
| `syslog_set(server_ip, port=514, facility="local0", severity="informational", enabled=True)` | `logging-server facility <f> severity <s> ipv4 <ip> port <p>`, `logging-service enable`, `logging severity <s>`; `enabled=false` sends `no logging-server …` with the same arguments. `server_ip` only from `SWITCH_SYSLOG_ALLOWED`. Severity keywords: `emergencies`, `alerts`, `critical`, `errors`, `warnings`, `notification`, `informational`, `debugging`. |
| `mgmt_services_set(http?, https?, disable_telnet=False)` | `set ip http {enable\|disable}`, `ip http secure server` / `no ip http secure server`, `no ip telnet service`. SSH cannot be changed, Telnet cannot be enabled. HTTP is disabled only after HTTPS reads back `Enabled` in the same session; HTTP and HTTPS cannot both be disabled in one call. |
| `clear_counters(port?, …)` | Privileged exec `clear counters [gigabitethernet 0/N]`. Resets the `counters_delta` baseline. |
| `system_identity_set(location?, contact?, name?)` | `system location`, `system contact` (values `[A-Za-z0-9 ._-]`, quoted when they contain a space), `set switch-name` (no spaces; sent last, the prompt is re-detected). |

Port write tools take `confirm_caution_port` (see `SWITCH_CAUTION_PORTS`).
Single ports only; `interface range` is not supported.

There are no VLAN, reboot, or reset tools.

Port format: `0/1` … `0/28` (no leading zeros). PoE: `0/1` … `0/24`.
The interface prefix the switch prints is accepted and normalised before
any check: `Gi0/15`, `gi 0/15` and `GigabitEthernet0/15` become `0/15`
(protected and caution ports apply to the normalised port).
Descriptions: 1–32 characters from `[A-Za-z0-9 ._-]`, with no leading or
trailing spaces. Quotes are not allowed in the input, so the wrapper's
own quoting cannot be broken out of.

## Security model

- **Default deny** for `show`. Only commands listed in `allowed_commands` run;
  `denied_commands` always wins. The allow list does not expand abbreviations
  (`sh sys info` is not `show system information`). See the netmiko-mcp 0.3.0 validator docs.
  The wrapper also rejects `|`, `;`, and newlines before that filter runs
  (`allow_pipe` is not honoured).
- **No free-form config.** Interface commands are built only by this package.
  The only other config sequence is the fixed best-effort
  `set cli pagination off` at session start (see [Paging](#paging)).
- **No VLAN, reboot, or reset tools.**
- **Protected ports, fail-closed.** `SWITCH_PROTECTED_PORTS` blocks
  `port_disable` and `poe_disable`, and every direction of the other port
  write tools (port security, storm control, rate limit, PoE cycle, cable
  diagnostics, clear counters on a named port) and, since 0.3.1,
  `port_set_description`. `port_enable` and `poe_enable` stay allowed. If
  the variable is
  unset, empty, or contains an invalid port identifier, those tools refuse
  every port.
- **Caution ports.** `SWITCH_CAUTION_PORTS` ports need
  `confirm_caution_port=true` for every port write (the description
  included since 0.3.1); the flag is in the audit log.
- **Dry run by default.** Every write tool (including `save_config` and the
  SNMP tools) defaults to `dry_run=true`: it returns the exact CLI lines,
  the current state and the expected state, and sends nothing.
- **Snapshot, error check, diff.** A real write stores a masked
  running-config snapshot first (`SWITCH_PRE_WRITE_SNAPSHOT`; not for
  `poe_cycle`, `cable_diag` and `clear_counters`, which leave the config
  unchanged), sends with
  `%` as netmiko `error_pattern` (it stops at the first rejected line),
  reads the state back and returns a before/after diff.
- **Host-key pinning.** `ssh_strict=True`, `system_host_keys=False`,
  `use_keys=False`, `allow_agent=False`, key file from `SWITCH_KNOWN_HOSTS`.
- **No connection at startup.** Missing or dummy environment is enough for
  `initialize` and `tools/list`.
- **One session per tool call**, serialized with a process-wide lock.
- **No automatic save.** Running-config changes die on reboot until
  `save_config`. In the hub, `save_config` and the SNMP write tools
  must be gated by `unlock`.
- **Audit log** records time, tool, parameters, allow/deny, and a short
  result (`ok`, `dry run`, or the error), plus a start line per call so a
  call cut off by a hub timeout or restart stays visible. Passwords are redacted from
  parameters, results, and error text (`***`). The SNMP community
  (`SWITCH_SNMP_COMMUNITY`) is redacted as `[REDACTED]`, including
  `show snmp community` listings.
- **Fail-closed redaction of device text** (0.3.0). On top of the exact
  secrets above, all device output (tool results, config backups and
  snapshots, error text, session log) goes through line rules: PEM blocks
  and long key blobs are removed; `snmp community|targetparams|group|user`
  lines keep only their keywords (SNMPv3 auth/priv keys masked);
  `password|secret|key <value>` is masked to the end of the line;
  `Label : value` lines whose label names a secret keep only status
  vocabulary (Enabled, MD5, None, …). Any other line that still contains
  `password|key|secret|community|auth|priv` is replaced by
  `[REDACTED-LINE]`. `show radius server` is strict: only `Label : value`
  lines survive, other lines become `[REDACTED-LINE]` (lines are replaced,
  never dropped, so an empty result means the device printed nothing).
  Parsers run on redacted text.
  Audit failures never abort a tool; they are reported on stderr and as an
  `audit_warning:` line in the result.
- **paramiko 4.0.0** for `ssh-rsa`/SHA-1 host keys. Do not bump to 5.x
  without a live SSH check.

## Paging

The LGS CLI (ISS-based firmware) pages long output. netmiko's `cisco_s300`
driver sends `terminal datadump`, which this firmware does not honour, and
`set cli pagination off` is rejected in privileged exec. This package
therefore:

1. Tries `set cli pagination off` in Global Configuration mode
   (`configure terminal` … `end`) at the start of each session, best effort.
   A rejection only logs one warning. The setting is a CLI display option; it
   would only persist if `save_config` is run afterwards. Set
   `SWITCH_PAGING_OFF=0` to skip it.
2. Runs every exec command (`show`, read-backs, `save`) through its own read
   loop: when the last visible line is a pager prompt (`--More--`,
   `-- More --`, `--More-- (NN%)`, `More: <space>, Quit: q …`,
   `<--- More --->`, `Press any key to continue`) it sends one space, and it
   finishes on the real prompt (`<hostname>#`). Pager text, backspaces, ANSI
   sequences, orphaned ESC bytes, other control characters, the command echo,
   and the trailing prompt are stripped. Blank lines directly before or after
   a page break (the pager's erase sequence, which netmiko turns into
   newlines, and trailing blanks at the end of a page) are dropped; blank
   lines elsewhere in the output are kept.
3. Gives up after `SWITCH_READ_TIMEOUT` seconds without new output. The error
   contains the last visible line, so an unknown pager prompt can be added.
4. For `save` only: if the last visible line ends in a Y/N confirmation
   (`(y/n)`, `[Y/N]`, `(yes/no)`, optionally followed by `:` or `?`), it
   answers `y` once. A second confirmation is not answered and fails. Any
   other prompt (for example `Are you sure?` or `[confirm]`) is not
   answered and runs into the timeout; `save_config` then reports that
   whether startup-config was written is unknown. `show` and read-backs
   never answer a confirmation. The real LGS328PC save prompt is **not
   live-confirmed** ([#4](https://github.com/WackEarl/lgs-switch-mcp/issues/4)).

## SNMP tools

These tools exist so Home Assistant can use a **non-default SNMPv2c
community** that is read-write (or read-only) but restricted to IF-MIB,
and so the default `public` / `private` communities and the default v3
user `noAuthUser` can be removed afterwards. They send only fixed
command sequences; there is no generic SNMP configure tool.

Creating a column in a write view (`snmp view <view> <column>
included`) and reading it back from `show snmp viewtree` were confirmed
in the 0.2.0 live check. **Community create/remove syntax and the SNMP
read/write path through an external client are not live-confirmed.**
`SWITCH_SNMP_WRITE_ENABLED` should stay unset (or anything other than
`1`) until then; the tools fail closed. The
command templates live in `src/lgs_switch_mcp/snmp_cli.py` and
cite their source. The primary source is the official Linksys LGSXXX
CLI User Manual, chapter 19
([MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf](https://downloads.linksys.com/support/assets/others/MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf)):

```
snmp view <ViewName> <OIDTree> included
snmp view <ViewName> <OIDTree> excluded
snmp group <GroupName> user <UserName> security-model v2c
snmp access <GroupName> v2c read <ReadView> write <WriteView|none> notify none
snmp community name <CommunityName> security <SecurityName>
no snmp community name <CommunityName>
no snmp user <UserName>
show snmp community
show snmp viewtree
show snmp group
show snmp group access
show snmp user
```

View names are compared exactly (case-sensitive). A view name that
differs from an existing view only in letter case (for example `wv` and
`WV`) is refused, because it is not confirmed whether the switch treats
view names case-sensitively.

This is **not** Cisco IOS (`snmp-server community X view V rw`). Generic
Aricent ISS documentation (Super Micro SNMP Configuration Guide, Cisco
Skylight/Flex SNMP commands) often uses `snmp community index <Index>
name <Name> security <Security>` and a `volatile|nonvolatile` storage
flag. The tools use the Linksys form **without** `index` and without
that flag. If the device rejects a command, stop and confirm the ISS
variant live; do not guess.

The community string is **only** read from `SWITCH_SNMP_COMMUNITY` (8–32
characters from `[A-Za-z0-9_]`, not `public`/`private`). It is never a
tool argument and is not reused as the group or security name (those are
derived as `<view>_grp` / `<view>_sec`). It is replaced with `[REDACTED]`
in tool output, audit entries, and exceptions, including `re.escape`/`repr`
forms and a wrapped `snmp community name … security` span. An invalid env
value is not used for redaction (and is warned at startup). SNMP write
tools disable the netmiko session log for that session so a community
echo cannot sit in the log in the clear. The `show` tool also disables
the session log for `show snmp community`, `show snmp viewtree`, and
`show snmp user`. `show snmp community` output is redacted even when it
is run through the `show` tool; session-log Community Name fields are
masked by label even when the name is not the configured secret.
Validation failures never echo the secret.

Suggested order, each call unlock-gated:

1. `snmp_view_create("<view>", "interfaces")` — OID `1.3.6.1.2.1.2`
2. `snmp_view_create("<view>", "ifmib")` — OID `1.3.6.1.2.1.31`
3. `snmp_view_create("<view>", "power-ethernet")` — OID
   `1.3.6.1.2.1.105`, so HA can read PoE state and budget
4. For `rw` only:
   `snmp_write_view_create("<view>_w", "ifAdminStatus")`,
   `snmp_write_view_create("<view>_w", "ifAlias")` and, for PoE
   switching, `snmp_write_view_create("<view>_w", "pethPsePortAdminEnable")`
5. `snmp_community_create("<view>", "rw", "<view>_w")` (or
   `snmp_community_create("<view>", "ro")`)
6. `snmp_community_remove("public")` then `snmp_community_remove("private")`
   — refused unless the configured community is present and mapped to a
   read view whose included subtrees are only on that allowlist (not
   `iso` / the whole tree) and, if it has write access, to a separate
   write view that passes the write-view check below
7. `snmp_user_remove("noAuthUser")`
8. `save_config` when you are ready to persist

### Read/write view split

A RW community never writes through its read view. `snmp access` names a
separate write view (manual p. 103: `read <ReadView | none> write
<WriteView | none>`), so the read view holds whole MIB subtrees (IF-MIB,
ifMIB, POWER-ETHERNET-MIB) while the write view holds only the writable
columns. A write view passes the check (before
binding, after `snmp_write_view_create`, after `snmp_community_create`,
and before `snmp_community_remove`) only if, in `show snmp viewtree`:

- every entry of the view has an explicit `included` / `excluded` type,
  an OID in a known format and an exact mask (see below);
- it includes at least one subtree, and its included subtrees are only
  the columns `1.3.6.1.2.1.2.2.1.7` (ifAdminStatus),
  `1.3.6.1.2.1.31.1.1.1.18` (ifAlias) and `1.3.6.1.2.1.105.1.1.1.3`
  (pethPsePortAdminEnable), never a whole MIB such as `1.3.6.1.2.1.2` or
  `1.3.6.1.2.1.105` and never an instance;
- it is not the same view as the read view.

Excluded entries (for example from an older build) only narrow a view and
are accepted, but none are required or sent.

`snmp_write_view_create` sends one line, `snmp view <view> <column>
included`, with netmiko `error_pattern="%"` (ISS error lines start with
`%`), then reads `show snmp viewtree` back and runs the check above. If
the column was already there, nothing is sent. On any error after
sending, the column added by this call is removed again (`no snmp view
<view> <column>`) and `show snmp viewtree` must match the state before
the call exactly; otherwise the result says `ROLLBACK NOT VERIFIED` and
the view must not be bound to a community. A column that existed before
the call is never removed. The rollback is the only place that sends
`no snmp view`.

OIDs from `show snmp viewtree` go through one normalization
(`oid_arcs`): whitespace, one leading dot, a leading `iso` (= `1`, only
when followed by `3`) and trailing dots are accepted, so `.1.3.6.1…`,
`iso.3.6.1…` and `1.3.6.1…` are the same OID; `iso.1.3.6.1…`, a bare
`iso` and other variants are refused instead of reinterpreted. Prefixes are compared by whole arcs, so
`1.3.6.1.2.1.105` is not below `1.3.6.1.2.1.10`. Any other format makes
the check refuse (fail-closed), in the read-view precheck as well.

Masks follow RFC 3415: bit *n* belongs to sub-identifier *n*, a missing
or short mask is extended with ones, and bits beyond the OID length do
not matter. A mask is exact when every bit that covers an arc of the OID
is 1. Accepted spellings: empty / `none` / `-`, dotted bits (`1`,
`1.1.1`) and hex octets (`ff`, `ff:e0`, `0xffe0`). The 0.2.0 live check
showed that after adding a column, the switch prints a mask with one `1`
per arc (`Subtree Mask : 1.1.1.1.1.1.1.1.1.1.1` for
`1.3.6.1.2.1.105.1.1.1.3`) and `Storage Type : Non-volatile` immediately.
The earlier read-only check printed `Subtree Mask : 1` for OID `1`. A
hex mask such as `ff:e0` for an 11-arc column is also accepted, while a
mask with a 0 inside the OID (a wildcard, such as `ff:c0` for an 11-arc
OID) is refused.

The viewtree parser reads the layout from the network admin's read-only check:

```
View Name    : iso
Subtree OID  : 1
Subtree Mask : 1
View Type    : Included
```

(no leading dot, no `iso.`, with a mask; the views on the switch are
`iso` and `restricted`). Blocks are split on `-----` lines and before
every `View Name` line, so blank-line separated blocks work too.

After a create, the access entry must name exactly the requested read and
write views. A failed check before sending refuses; after sending it is
reported as "Configuration was sent, verification failed". Read views
are also refused if any of their entries has an unrecognised mask.

### PoE over SNMP

Home Assistant reads bandwidth counters from IF-MIB / ifMIB and PoE
state (detection status, power budget) from POWER-ETHERNET-MIB
`1.3.6.1.2.1.105`, which is **not** inside IF-MIB, through the read view.
It switches ports with `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`), sets
descriptions with `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`), and turns PoE
on or off with `pethPsePortAdminEnable` (`1.3.6.1.2.1.105.1.1.1.3`)
through the write view (decision in Vikunja task 48). Only that PoE
column is writable, never the whole PoE MIB.

pethPsePortTable is indexed by
`pethPsePortGroupIndex.pethPsePortIndex`, which need not equal the port
number or the ifIndex. Whether the LGS328PC implements
`1.3.6.1.2.1.105` (or only a vendor MIB) is unconfirmed; if it does not,
the fallback is PoE read-only (no `pethPsePortAdminEnable` in the write
view).

> **Note on 0/15:** 0/15 feeds a LINOVISION EoC converter that powers the
> Zigbee router at the far end over PoE. Do **not** turn PoE (or the
> port) off on 0/15, or the Zigbee router goes down. The owner decided
> against a hard lock (task 48, comment 69): 0/15 is not in
> `SWITCH_PROTECTED_PORTS`. Since 0.3.0 it can be listed in
> `SWITCH_CAUTION_PORTS`, so the CLI port write tools need
> `confirm_caution_port=true`; SNMP does not block it.
> In Home Assistant its PoE and port switches should be disabled.

### SNMP and protected ports

**The protected ports are only protected at tool level.**
`SWITCH_PROTECTED_PORTS` (production: `0/10`, which powers the Unraid
server through a PoE splitter, and `0/24`, the uplink) is enforced by
the tools of this server: `port_disable`, `poe_disable` and the 0.3.0
port write tools refuse those ports, and refuse every port if the
variable is unset, empty or invalid (fail-closed). This server has no
tool that writes SNMP values itself.

There is **no** protection at SNMP level (the owner's decision of
2026-11-13; earlier builds excluded the protected ports in the write
view, which needed live ifIndex / PoE index mappings). The write view
makes `ifAdminStatus`, `ifAlias` and `pethPsePortAdminEnable` writable
for **every** port. Anyone who has the write community can switch off
0/10 or 0/24 (or cut their PoE) with a direct SNMP SET, past these tools;
the switch then needs local access to recover. Therefore:

- keep the write community secret and use it only where it is needed
  (Home Assistant); give everything else a read-only community;
- keep the write view to the columns that are really used (leave out
  `pethPsePortAdminEnable` if PoE switching is not needed);
- restrict UDP/161 at the firewall to the hosts that need it (the network
  admin handles the ACL as a separate work package); these tools set no
  source-IP / `transporttag` restriction;
- disable the HA switches for 0/10, 0/24 and 0/15.

### Live-test checklist (network admin)

Confirmed in the 0.2.0 live check (see [Live-test status](#live-test-status)):

- Refused config lines print an error starting with `%` (`% Invalid
  input detected at '^' marker`).
- `show snmp view` is an alias of `show snmp viewtree`.
- After `snmp_write_view_create`, `show snmp viewtree` prints the column
  OID as given (no leading dot), a mask of one `1` per arc
  (`1.1.1.1.1.1.1.1.1.1.1` for `1.3.6.1.2.1.105.1.1.1.3`), `View Type :
  Included`, and `Storage Type : Non-volatile` immediately, without
  `save_config`. The column is accepted without a mask in the create
  command.

Still unconfirmed:

- Exact syntax: does `snmp community name … security …` work, or is the
  ISS `index` form required? (The switch lists communities under a
  Community Index, so the `index` form may be needed.) Is `notify none`
  / `write none` accepted?
- Storage type of a new group / community and whether `save_config`
  actually persists them (new views are already Non-volatile).
- Whether `enable snmpagent` is required first.
- Exact `show snmp community`, `show snmp group`, `show snmp group
  access`, and `show snmp user` layouts (the parsers assume ISS
  `Key: value` blocks separated by `-----`; `show snmp viewtree` is
  confirmed, see above).
- Exact spelling of the default communities and of `noAuthUser`.
- SET of `ifAlias` with the new view.
- That `no snmp view <view> <oid>` removes exactly that entry (used
  for rollback; not triggered in the 0.2.0 check).
- That a GET/WALK of `1.3.6.1.2.1.105` works with the community and a
  SET of `pethPsePortAdminEnable` and `ifAdminStatus` works on a free
  port (e.g. 0/18) through an external SNMP client. If PoE SET fails,
  fall back to PoE read-only. Do **not** SET 0/10 or 0/24: nothing at
  SNMP level stops it.
- Confirm leftover `public` / `private` / `noAuthUser` are gone, and
  that the session log and tool output never contain the community.
- Terminal width: `cisco_s300` `session_preparation` already sends
  `terminal width 511`. Confirm that is in effect (no extra width
  command is sent by these tools) and that `snmp community` lines do
  not wrap mid-secret in a way that a later live check would miss.

## What is new in 0.3.0

- **Breaking:** `port_set_admin_state` and `poe_set` are replaced by
  `port_enable` / `port_disable` and `poe_enable` / `poe_disable`, so the
  hub can lock the disabling direction only. Every write tool, including
  `port_set_description`, `save_config` and the SNMP tools, now defaults to
  `dry_run=true`; callers must pass `dry_run=false` to change anything.
  Write results are JSON.
- New read and write tools (see [Tools](#tools)).
- New `commands.yml` entries (read-only): `show logging-server`,
  `show security-suite`, `show access-lists [*]`, `show port-isolation
  status`, `show monitor [*]`, `show ip dns name-server`, `show clock
  properties`, `show dot1x [*]`, `show radius server` (strict
  redaction), `show rmon [*]`, `show qos global info`, `show priority-map`,
  `show class-policy`, `show scheduler`, `show ip igmp snooping [*]`,
  `show ipv6 mld snooping [*]`, `show voice vlan`, `show ipv6 interface`,
  `show ipv6 route`, `show cli`, `show history`, `show ip http secure
  server status`. `show running-config`, `show startup-config`, `show
  current*`, cable diagnostics, other `show radius` commands and the
  broad SNMP dumps stay denied for `show`.
- Not included on purpose: port mirroring (an automatic removal after N
  minutes cannot be guaranteed by a stdio server that the hub stops when
  idle), management ACLs (lock-out risk; a click guide instead),
  TFTP config export (only needed if `show running-config` does not exist
  on this firmware), environment / SFP values (no CLI command in the
  manual; find them with `show_help` first), speed/duplex, VLANs,
  users/passwords, reboot/reset, SSH off, Telnet on, LAG/STP, `interface
  range`, free-form config.

## What is new in 0.3.2

Fixes from the read-only retest of 0.3.1. After that retest the
switch's SSH service stopped answering; 0.3.2 rebuilds the session
handling so the server cannot pile up SSH sessions on the switch:

- **SSH sessions:** at most one SSH session to the switch at a time,
  shared by tool calls and the background config dump. A clean session
  is kept for `SWITCH_SESSION_IDLE` seconds (default 10) and reused,
  then logged out with `exit`. A session that ends in a timeout is
  aborted (Ctrl-C, pager quit, output drained), logged out with `exit`
  (`end` first in config mode) within `SWITCH_LOGOUT_TIMEOUT`, and only
  then is the transport closed hard. No session is ever left open.
- **Connect leak:** netmiko kept an authenticated SSH transport open
  when opening the shell channel failed during connect (the connection
  object never reached the caller). The connection is now opened in two
  steps so a failed connect is always closed.
- **Reconnect protection:** after a command timeout or a failed or slow
  connect no new connection is opened for `SWITCH_COOLDOWN_BASE` seconds
  (default 30, doubling per failure up to `SWITCH_COOLDOWN_MAX`, default
  600; kept across restarts). Calls answer `Switch cooling down …; retry
  in Ns` at once. Nothing retries automatically; the only exception is
  `poe_cycle` switching PoE back on once after a failed cycle.
- **Shutdown:** on process end (stdin closed, SIGTERM, SIGHUP) the kept
  session is logged out.
- **Timeouts and the session hang:** a call that outlived the caller's
  request timeout (MCP `-32001`) kept the session lock, and every later
  call queued behind it, also after `wake_server`. Every call now has a
  wall-clock budget (`SWITCH_CALL_BUDGET`, default 45 s) for the lock
  wait, the connect and each command, also while a device keeps sending.
  The lock wait is bounded, so a hung call cannot block later calls.
- **config_read / config_backup / config_diff:** the running-config dump
  runs in the background; a slow dump answers `Pending` instead of
  running into the caller's timeout, and the next call gets the result.
- **PoE parser:** `admin` (column `State`) and `auto_class` (from the
  Power Limit Type) are filled for the live LGS328PC layout.
- **Ports:** `Gi0/15`-style ports are accepted everywhere a switch port
  is a parameter, normalised to `0/15` before the protected and caution
  port checks.
- **health_summary:** an environment show that is not on the allowlist
  is named in `environment_skipped` instead of being left out silently.
- **audit_tail:** `unfinished` entries carry `age_ms`.

## What is new in 0.3.1

Fixes from the first live check of 0.3.0 on the LGS328PC (firmware
1.01.02.02, read tools only):

- **Config reads:** the running-config is read with `show current
  running-config`. The LGS has no show command for the startup-config:
  `config_read("startup")` / `config_backup("startup")` answer
  `Not available:` without sending anything. The pre-write snapshot uses
  the running-config, so `SWITCH_PRE_WRITE_SNAPSHOT=required` works again.
- **save_config / config_diff:** a real `save_config` stores the masked
  running-config it saves (tag `pre-save`); that copy is the baseline for
  `config_diff` and for the next save's diff. Saves done outside this
  server are not seen; `Config Save Status` is always returned.
- **PoE parser:** the Port column holds `1`–`24`; multi-word columns
  (`Power Limit Type`, `Auto Class`, `Max Power(W)`) no longer leak into
  the power, class or device fields. New fields `max_power_w`,
  `auto_class`, `limit_type`.
- **VLAN parser:** `show vlan` key/value blocks (`Vlan ID : 1`, `Member
  Ports : …`, `Untagged Ports : …`, wrapped lines, `Po` ports);
  `port_status` reports a `parse_warning` when nothing is recognised.
- **Allowlist (`examples/commands.yml`):** `show monitor all` and `show
  monitor session *` instead of the incomplete `show monitor`; `show
  priority-map in-priority-type` instead of `show priority-map`; `show
  version` moved to the deny list (invalid on the LGS); new `show device
  temperature`, `show system fan`, `show system utilization`, also read
  by `health_summary`. There is no `show authorized-manager` (nor `show
  env*`, `show cpu*`, `show memory*`).
- **show_help:** a `snmp   SNMP information` help line was hidden as
  `[REDACTED-LINE]` (it looked like an SNMP config line). Help entries
  without a sensitive word are kept now; the other rules are unchanged.
- **show radius server:** returned an empty result live. Strict redaction
  replaces lines but never removes them, so the device printed nothing
  (no RADIUS server configured), even though 802.1X uses RADIUS.
- **Audit:** every call writes a start line; a call that never returns
  (hub timeout `-32001`, restart) shows up as `unfinished` in
  `audit_tail`. Result lines carry `call_id` and `duration_ms`.
- **port_set_description:** refuses protected ports and needs
  `confirm_caution_port=true` on caution ports (**behaviour change**).
- **Tool descriptions** name the configured protected and caution ports
  (read from `SWITCH_PROTECTED_PORTS` / `SWITCH_CAUTION_PORTS` at start).
- **mac_table:** the listing showed 54 entries (with the device's own
  total line), `show mac-address-table count` reported 85 dynamic
  addresses. The listing is complete, so the gap is the device's
  counting; `count_note` reports it instead of guessing.

## Retest 0.3.2 (network admin)

1. `config_read()`: masked running-config, or `Pending` first and the
   result on the next call. No hub timeout. Then `config_backup()` and
   `config_diff()`.
2. `show users`: a result or a tool error within about 45 s, no `-32001`;
   right after it `show clock` works.
3. `health_summary`: `environment.fan` present (deployed `commands.yml`
   needs `show system fan status`), or `environment_skipped` says why.
4. `poe_status`: `admin` and `auto_class` filled.
5. `port_counters(port="Gi0/15")` works like `port="0/15"`; write tools
   with `dry_run=true` refuse `Gi0/10` and `Gi0/24` as protected ports.
6. `audit_tail`: finished calls with `duration_ms`, cut-off ones as
   `unfinished` with `age_ms`.
7. Sessions: restart the MCP server once after the update so SSH
   sessions left by 0.3.1 are gone, and check in the switch's web UI
   that no old SSH sessions remain. Two read calls within 10 s use one
   login (audit log, switch log); about 10 s after the last call the
   session is gone again.
8. Cooldown: one `show users` that runs into the call budget is
   followed by `Switch cooling down …; retry in 30s` for the next call,
   without a new login. After the cooldown one call works again.

## Retest 0.3.1 (network admin)

1. `config_read()` returns the masked running-config; `config_read("startup")`
   answers `Not available`. No secret visible in the config.
2. `config_backup()`, then `config_diff()` (no baseline yet: only the status).
3. `poe_status`, `health_summary`, `port_status` with `include_raw=true`:
   PoE ports, VLANs and `environment` filled, `parse_warnings` empty.
4. `show monitor all`, `show priority-map in-priority-type vlanPri` (and
   `ipDscp`), `show device temperature`, `show system fan status`, `show
   system utilization`; `show
   version` is refused.
5. `show_help("")`: no `[REDACTED-LINE]` between `security-suite` and
   `snmp-server`.
6. `audit_tail`: start and result lines folded, `duration_ms` present.
7. The write checks 7–13 of the 0.3.0 list below (not run yet), including
   `save_config` (now: stored copy and diff to the previous save).

## Live test 0.3.0 (network admin)

Results of the first check (read tools only) are in "What is new in
0.3.1"; points 7–13 are still open. The original list, in this order:

1. `show running-config` and `show startup-config` exist (`config_read`
   for both). Result: only `show current running-config` exists, no
   startup show (fixed in 0.3.1).
2. `config_read` output: no secret is visible (communities, SNMPv3 keys,
   user passwords, RADIUS key, certificates); structure stays readable.
3. Parsers against real output: `health_summary`, `port_status`,
   `port_counters`, `mac_table`, `lldp_neighbors`, `poe_status` with
   `include_raw=true`; `parse_warnings` should be empty.
4. New `show` entries from the list above, one by one; especially that
   `show radius server` hides the key.
5. `show_help("")`, `show_help("interfaces")`: help listing comes back,
   the prompt is clean afterwards, nothing is executed. Then look for
   `show env*`, `show cpu*`, `show memory*`, `show storm-control*`,
   `authorized-manager`.
6. `counters_delta` twice (baseline, then delta).
7. Dry runs of every write tool; then on a free port (e.g. 0/18), with
   `dry_run=false`: `port_security_set` (limit, then off),
   `storm_control_set` (then off), `rate_limit_set` (then off),
   `poe_cycle`, `cable_diag`, `clear_counters("0/18")`. Confirm
   the read-backs and the interface block of the running-config.
8. `syslog_set` to the allow-listed receiver, then `enabled=false`: does
   `no logging-server …` with the full arguments remove the entry?
9. `system_identity_set(location=…, contact=…)`; quoting of values with
   spaces. `name` only if a prompt change is acceptable (the prompt is
   re-detected; a broken session afterwards would show here).
10. `mgmt_services_set(https=true)`, check HTTPS in a browser, then
    `mgmt_services_set(http=false)`; read-back wording of `show ip http
    secure server status` (`Enabled`/`Disabled`).
11. `clear_counters()` without port: does it ask for a confirmation?
12. `save_config(dry_run=true)`, then `dry_run=false`: stored copy of the
    saved running-config, diff and `Config Save Status`; the save prompt (#4).
13. Protected ports: every port write tool except `port_enable` and
    `poe_enable` refuses the protected ports (`port_set_description`
    included since 0.3.1); caution ports need `confirm_caution_port=true`.
14. `audit_tail` shows the calls above, without secrets.

## Live-test status

Confirmed on LGS328PC, firmware 1.01.02.02, in the 0.2.0 live check
(network admin, commit 177dc84, 2026-11-13):

- Device error lines start with `%` (example: `% Invalid input
  detected at '^' marker`).
- `snmp view <view> <column> included` (no mask) is accepted for a
  write-view column such as `1.3.6.1.2.1.105.1.1.1.3` or
  `1.3.6.1.2.1.2.2.1.7`.
- `show snmp viewtree` prints `Subtree OID  : 1.3.6.1.2.1.105.1.1.1.3`
  / `Subtree Mask : 1.1.1.1.1.1.1.1.1.1.1` (one `1` per arc),
  `View Type : Included`, `Storage Type : Non-volatile` immediately
  (no `save_config`), `Row Status : Active`. `show snmp view` is an
  alias of `viewtree`.
- `port_set_admin_state` and `poe_set` (CLI, not SNMP; 0.3.0 replaces
  them with `port_enable` / `port_disable` / `poe_enable` / `poe_disable`
  that send the same commands) worked on a free port (0/18) and were
  reversed.

Not verified in that check:

- The SNMP read/write path through an external client (GET/WALK of
  `1.3.6.1.2.1.105`, SET of `pethPsePortAdminEnable` / `ifAdminStatus`
  / `ifAlias`).
- Community create/remove syntax (the switch lists communities under a
  Community Index, so the ISS form with `index` may be required).
- `no snmp view <view> <oid>` removing exactly one entry.

Confirmed on LGS328PC, firmware 1.01.02.02 (0.1.0 and 0.1.1 live tests):

- paramiko 4.0.0 negotiates `ssh-rsa`/SHA-1; strict host-key check works.
- Login lands directly in privilege 15 (`LGS328PC#`); no enable needed, no
  banner, no second login prompt.
- `show version` does not exist; use `show system information`.
- Read-back `show power inline gigabitethernet 0/N` works.
- Read-back `show interfaces gigabitethernet 0/N` works; output starts with
  e.g. `Gi0/24 up, line protocol is up (connected)`.
- The pager loop completes long outputs (`show interfaces status`,
  `show power inline`, `show interfaces gigabitethernet 0/24`), tested with
  `SWITCH_PAGING_OFF=0`.
- Error heuristic: after ANSI/control stripping, a line is a failure if it
  contains `%` anywhere (including a same-line prompt such as
  `LGS328PC(config-if)#% Invalid input`), or if — after removing a leading
  prompt (`hostname`, optional `(config…)`, then `#` or `>`) — the remainder
  is not empty, is not one of the commands just sent (compared after
  dropping double quotes and collapsing whitespace), and contains the word
  `Error` or `Invalid` (case-insensitive). Echoed commands such as
  `description "Error LED"` or the unquoted echo `description Error LED`
  are skipped. Invalid commands on this firmware
  return `% Invalid input detected` (confirmed live).
- `description <two words>` unquoted is rejected (`% Invalid input detected`
  at the second word); fixed in 0.1.2 by quoting.

Still to confirm with 0.1.2:

- Quoted `description "<text>"` is accepted and shown without quotes in
  `show interfaces description`. The exact table layout of that command
  is assumed (Cisco/ISS-style fixed-width `Description` column, `Gi0/N`
  rows) and should be confirmed live.
- Page breaks without leftover ESC bytes or blank lines.
- Whether `set cli pagination off` in config mode is accepted.
- The other interface tools (`shutdown`, `power inline …`) and the output of
  `save`, including whether it asks for a confirmation and its exact text
  ([#4](https://github.com/WackEarl/lgs-switch-mcp/issues/4)).
- Hub `unlock` behaviour for `save_config`.

## Credits

This repository's own code is licensed under the MIT License (`LICENSE`).
It is not a fork of the projects below. It depends on them at runtime and
follows netmiko-mcp's `commands.yml` format; their sources are not vendored
here. Copyright notices are also in `NOTICE`.

- [netmiko](https://github.com/ktbyers/netmiko) by Kirk Byers, MIT License
- [netmiko-mcp](https://github.com/ktbyers/netmiko_mcp) by Kirk Byers, Apache License 2.0

## Development

```bash
uv sync --extra dev
uv run --extra dev pytest
```

Pinned runtime dependencies: `netmiko==4.8.0`, `paramiko==4.0.0`,
`netmiko-mcp==0.3.0`, `mcp==2.3.0`.
