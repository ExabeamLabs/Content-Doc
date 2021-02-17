#### Parser Content
```Java
{
Name = raw-vpn-timeout
  Vendor = Juniper Networks
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Session timed out for""", """ (session:""" ]
  Fields = [
    """({time}\d+-\d+-\d+ \d\d:\d\d:\d\d) \-""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\d{4}-\d{2}-\d{2} \d\d:\d\d:\d\d\s+-\s+({host}[\w\.-]+)\s+-\s+\[""",
    """\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+""",
    """Session timed out for (?:({user_email}[^@\\\/]+@[^@\/\s]+)|({user}[^/]+))""",
    """({host}[\w\-.]+)\s+\S+\s+PulseSecure:""",
    """PulseSecure:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@\\\/]+@[^@\(\s]+?)|({user}[^\s]+))\(({realm}[^\)]+)?"""
  ]
  DupFields = [ "host->dest_host" ]
}
```