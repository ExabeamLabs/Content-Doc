#### Parser Content
```Java
{
Name = iptables-network-connection-failed
  Vendor = IPTables
  Product = IPTables
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ kernel: """, """ DENY """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """({host}[\w.\-]+)\s+kernel:\s""",
    """\sIN=({src_interface}[^=]+?)(\s+\w+=|\s*$)""",
    """\sOUT=({dest_interface}[^=]+?)(\s+\w+=|\s*$)""",
    """\sMAC=({src_mac}[^=]+?)(\s+\w+=|\s*$)""",
    """\sSRC=({src_ip}[a-fA-F\d.:]+)""",
    """\sDST=({dest_ip}[a-fA-F\d.:]+)""",
    """\sPROTO=({protocol}[^=]+?)(\s+\w+=|\s*$)""",
    """\sSPT=({src_port}\d+)""",
    """\sDPT=({dest_port}\d+)""",
  ]
}
```