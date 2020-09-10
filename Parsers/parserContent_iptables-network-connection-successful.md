#### Parser Content
```Java
{
Name = iptables-network-connection-successful
  Vendor = IPTables
  Product = IPTables
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ kernel: """, """ ACCEPT """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """({host}[\w.\-]+)\s+kernel:\s""",
    """\sIN=({src_interface}[^=]+?)\s+\w+=""",
    """\sOUT=({dest_interface}[^=]+?)\s+\w+=""",
    """\sMAC=({src_mac}[^=]+?)(\s+\w+=|\s*$)""",
    """\sSRC=({src_ip}[a-fA-F\d.:]+)""",
    """\sDST=({dest_ip}[a-fA-F\d.:]+)""",
    """\sPROTO=({protocol}[^=]+?)\s+\w+=""",
    """\sSPT=({src_port}\d+)""",
    """\sDPT=({dest_port}\d+)""",
  ]
}
```