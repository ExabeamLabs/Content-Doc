#### Parser Content
```Java
{
Name = raw-vpn-timeout
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Session timed out for""", """ (session:""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d) \-""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """\d{4}-\d{2}-\d{2} \d\d:\d\d:\d\d\s{1,100}-\s{1,100}({host}[\w\.-]+)\s{1,100}-\s{1,100}\[""",
    """\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}""",
    """Session timed out for (?:({user_email}[^@\\\/]+@[^@\/\s]+)|({user}[^/]+))""",
    """({host}[\w\-.]+)\s{1,100}PulseSecure:""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\\\/]+@[^@\(\s]+?)|({user}[^\s]+))\(({realm}[^\)]+)?"""
  ]
  DupFields = [ "host->dest_host" ]
}
```