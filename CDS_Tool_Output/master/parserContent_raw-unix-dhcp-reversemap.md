#### Parser Content
```Java
{
Name = raw-unix-dhcp-reversemap
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Added reverse map from " ]
  Fields = [ """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\s({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s\w+\[""",
    """Added reverse map from ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+? to ({dest_host}[^\s"$]+)"""
  ]
  DupFields = [ "dest_host->user" ]
}

{
  Name = raw-unix-dns-appliedadd
  Vendor = Unix
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " applied ADD for ", "IN A" ]
  Fields = [ """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """applied ADD for '({dest_host}[^']+).+? IN A ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```