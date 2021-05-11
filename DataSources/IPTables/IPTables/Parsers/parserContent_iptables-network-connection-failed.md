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
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """({host}[\w.\-]+)\s{1,100}kernel:\s""",
    """\sIN=({src_interface}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sOUT=({dest_interface}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sMAC=({src_mac}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sSRC=({src_ip}[a-fA-F\d.:]+)""",
    """\sDST=({dest_ip}[a-fA-F\d.:]+)""",
    """\sPROTO=({protocol}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sSPT=({src_port}\d{1,100})""",
    """\sDPT=({dest_port}\d{1,100})""",
  ]
}
```