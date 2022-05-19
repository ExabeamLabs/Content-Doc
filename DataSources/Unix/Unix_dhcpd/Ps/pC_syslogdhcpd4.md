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
    """\d\d:\d\d:\d\d\s{1,100}({host}.+?)\s{1,100}dhcpd: Forward map from ({dest_host}[^\s]{1,2000}) to ({dest_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}({additional_info}.+?)\.*\s{0,100}"{0,20}$""",
  ]
  DupFields = [ "dest_host->user" ]


}
```