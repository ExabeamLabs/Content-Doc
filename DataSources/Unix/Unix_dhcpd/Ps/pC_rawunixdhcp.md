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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}dhcpd""",
    """DHCPREQUEST for ({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """from ({dest_mac}[A-Fa-f:\d.]{1,2000})( \((?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})({dest_host}[^)]{1,2000})\))? via ({dest_interface}[^\s"]{1,2000})""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),Renewed,({dest_host}[^,]{1,2000})"""
  ]
  DupFields = [ "dest_host->user" ]


}
```