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
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """({host}[\w.\-]{1,2000})\s{1,100}kernel:\s""",
    """\sIN=({src_interface}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sOUT=({dest_interface}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sMAC=({src_mac}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sSRC=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sDST=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sPROTO=({protocol}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sSPT=({src_port}\d{1,100})""",
    """\sDPT=({dest_port}\d{1,100})""",
  ]
}
```