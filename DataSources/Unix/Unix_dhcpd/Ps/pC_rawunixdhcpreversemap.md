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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\s({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s\w+\[""",
    """Added reverse map from ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+? to ({dest_host}[^\s"$]{1,2000})"""
  ]
  DupFields = [ "dest_host->user" ]


}
```