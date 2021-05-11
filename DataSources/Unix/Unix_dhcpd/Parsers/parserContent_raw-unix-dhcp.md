#### Parser Content
```Java
{
Name = raw-unix-dhcp
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "dhcpd","DHCPREQUEST for" ]
  Fields = [ 
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]+)\s{1,100}dhcpd""",
    """DHCPREQUEST for ({dest_ip}[A-Fa-f:\d.]+)""",
    """from ({dest_mac}[A-Fa-f:\d.]+)( \((?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})({dest_host}[^)]+)\))? via ({dest_interface}[^\s"]+)""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),Renewed,({dest_host}[^,]+)"""
  ]
  DupFields = [ "dest_host->user" ]
}
```