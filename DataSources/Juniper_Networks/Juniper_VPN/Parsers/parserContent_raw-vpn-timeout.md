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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\d{4}-\d{2}-\d{2} \d\d:\d\d:\d\d\s{1,100}-\s{1,100}({host}[\w\.-]{1,2000})\s{1,100}-\s{1,100}\[""",
    """\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}""",
    """Session timed out for (?:({user_email}[^@\\\/]{1,2000}@[^@\/\s]{1,2000})|({user}[^/]{1,2000}))""",
    """({host}[\w\-.]{1,2000})\s{1,100}PulseSecure:""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\\\/]{1,2000}@[^@\(\s]{1,2000}?)|({user}[^\s]{1,2000}))\(({realm}[^\)]{1,2000})?"""
  ]
  DupFields = [ "host->dest_host" ]
}
```