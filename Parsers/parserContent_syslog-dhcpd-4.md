#### Parser Content
```Java
{
Name = syslog-dhcpd-4
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [""" dhcpd: """, """ Forward map from """]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s+({host}.+?)\s+dhcpd: Forward map from ({dest_host}[^\s]+) to ({dest_ip}[A-Fa-f:\d.]+)\s+({additional_info}.+?)\.*\s*"*$""",
  ]
  DupFields = [ "dest_host->user" ]
}
```