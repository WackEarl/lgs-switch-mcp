"""LGS328PC outputs for the 0.3.1 tests, rebuilt from the live check of
0.3.0 (FW 1.01.02.02, read tools only).

The live check report described the layouts (column names, value formats,
counts) but did not include the raw device text, so these samples follow
that description: the PoE Port column holds 1..24, ``Power Limit Type``
and ``Auto Class`` are multi-word columns, ``show vlan`` prints key/value
blocks. No secrets; addresses are documentation examples.
"""

# show power inline: Port column 1..24, multi-word columns.
POWER_INLINE = """
Port  Admin   Oper  Power Limit Type  Power(W)  Max Power(W)  Class  Auto Class  Priority
----  ------  ----  ----------------  --------  ------------  -----  ----------  --------
1     Enable  On    Class Based       5.4       30.0          2      Enabled     Low
2     Enable  Off   Class Based       0.0       30.0          0      Enabled     Low
15    Enable  On    User Defined      3.1       15.4          1      Disabled    High
24    Enable  Off   Class Based       0.0       30.0          0      Enabled     Critical
"""

# The same table with a single dash line (no column breaks) under the header.
POWER_INLINE_ONE_RULE = """
Port  Admin   Oper  Power Limit Type  Power(W)  Max Power(W)  Class  Auto Class  Priority
------------------------------------------------------------------------------------------
1     Enable  On    Class Based       5.4       30.0          2      Enabled     Low
15    Enable  On    User Defined      3.1       15.4          1      Disabled    High
"""

# show vlan: key/value blocks; long member lists wrap onto indented lines.
VLAN_KV = """
Vlan database
-------------
Vlan ID             : 1
Member Ports        : Gi0/1, Gi0/2, Gi0/3, Gi0/4, Gi0/5, Gi0/6, Gi0/7, Gi0/8
                      Gi0/9, Gi0/10, Gi0/15, Gi0/24, Po1
Untagged Ports      : Gi0/1, Gi0/2, Gi0/3, Gi0/4, Gi0/5, Gi0/6, Gi0/7, Gi0/8
                      Gi0/9, Gi0/10, Gi0/15, Po1
Forbidden Ports     : None
Name                : default
Status              : Permanent
----------------------------------------------------
Vlan ID             : 20
Member Ports        : Gi0/24, Gi0/18
Untagged Ports      : Gi0/18
Forbidden Ports     : None
Name                : iot
Status              : Permanent
----------------------------------------------------
"""

VLAN_KV_UNREADABLE = """
Vlan ID             : 1
Member Ports        : port-list-in-an-unknown-format
Untagged Ports      : None
"""

# show mac-address-table: complete listing with its own footer, while the
# count command reports more dynamic addresses (54 vs 85 live).
MAC = """
Vlan  Mac Address          Type     Ports
----  -------------------  -------  -------
1     00:11:22:aa:bb:01    Learnt   Gi0/1
1     00:11:22:aa:bb:02    Learnt   Gi0/15

Total Mac Addresses displayed: 2
"""
MAC_COUNT = """
Dynamic Unicast Address Count : 3
Static Unicast Address Count  : 0
"""

# show_help("") excerpt: the "snmp" entry sits between security-suite and
# snmp-server, where 0.3.0 printed [REDACTED-LINE].
HELP_TOP = """LGS328PC# show ?
  security-suite        Show security suite information
  snmp                  SNMP information
  snmp-server           SNMP server information
  ssh-configurations    Show SSH configurations
LGS328PC# show """

# Environment shows (layouts not recorded; key/value guess).
TEMPERATURE = """
Unit   Sensor   Temperature(C)   Status
----   ------   --------------   ------
1      1        41               OK
"""
FAN = """
Fan 1 Status : OK
Fan 2 Status : OK
"""
UTILIZATION = """
CPU Utilization (5 sec) : 7 %
Memory Utilization      : 48 %
"""
