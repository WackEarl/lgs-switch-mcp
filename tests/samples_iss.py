"""Synthetic ISS-style outputs for the 0.3.0 parser tests.

Written from the LGS CLI manual layouts; not recorded on a device. Replace
or extend with recorded outputs after the live check (see README).
"""

SYSTEM = """
Switch Name: LGS328PC
Switch Location: Default Location
Switch Contact: Default Contact
System MAC Address: 00:11:22:33:44:55
Firmware Version : 1.01.02.02
System Up Time : 35 days, 4 hours, 12 minutes
Config Save Status : Saved
"""
POWER_DETAIL = """
Unit  Nominal Power  Consumed Power  Usage Threshold
----  -------------  --------------  ---------------
"""
POWER_DETAIL_KV = """
Power Budget : 250.0 W
Power Consumption : 67.6 W
Usage Threshold : 95 %
"""
POWER_INLINE = """
Port     Admin   Oper     Power(W)  Class  Device         Priority
-------  ------  -------  --------  -----  -------------  --------
Gi0/1    Auto    On       5.4       2      AP-Floor1      Low
Gi0/2    Auto    Off      0.0       0                     Low
Gi0/15   Auto    On       3.1       1                     High
"""
STATUS = """
Port     Name           Status         Vlan   Duplex  Speed  Type
-------  -------------  -------------  -----  ------  -----  ---------
Gi0/1    AP-Floor1      connected      1      Full    1000   Copper
Gi0/2                   notconnect     1      Auto    Auto   Copper
Gi0/15   EoC Zigbee     connected      1      Full    100    Copper
"""
COUNTERS = """
Port     InOctets    InUcastPkts  InDiscards  InErrs
-------  ----------  -----------  ----------  ------
Gi0/1    123456      1000         0           0
Gi0/15   654321      2000         115         21

Port     OutOctets   OutUcastPkts  OutDiscards  OutErrs
-------  ----------  ------------  -----------  -------
Gi0/1    222222      1500          0            0
Gi0/15   333333      2500          0            0
"""
COUNTERS2 = COUNTERS.replace("115         21", "118         25")
LOGGING = """
Logging Severity : Critical
Buffered log entries : 2
<2>Nov 26 10:01:02 LGS328PC: Login from 192.0.2.124 via SSH
<2>Nov 26 11:05:00 LGS328PC: Port Gi0/2 link down
"""
DESCRIPTION = """
Interface   Status   Description
---------   ------   -----------
Gi0/1       up       AP-Floor1
Gi0/2       down
Gi0/15      up       EoC Zigbee
"""
VLAN = """
Vlan  Name      Ports               Type
----  --------  ------------------  -------
1     default   Gi0/1-2, Gi0/15     Untagged
"""
LLDP = """
Capability Codes : (R)Router,(B)Bridge,(T)Telephone

Device ID         Local Intf     Hold-time   Capability   Port Id
----------------  -------------  ----------  -----------  ---------
fritz.box         Gi0/24         120         R            lan1
ap-floor1         Gi0/1          120         B            eth0

Total Entries Displayed: 2
"""
MAC = """
Vlan  Mac Address          Type     Ports
----  -------------------  -------  -------
1     00:11:22:aa:bb:01    Learnt   Gi0/1
1     00:11:22:aa:bb:02    Learnt   Gi0/15

Total Mac Addresses displayed: 2
"""
MAC_COUNT = """
Dynamic Address Count : 2
Static Address Count : 0
Total Mac Addresses : 2
"""
