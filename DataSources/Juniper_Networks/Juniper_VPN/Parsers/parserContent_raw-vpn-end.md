#### Parser Content
```Java
{
Name = raw-vpn-end
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ Logout from """, """ (session:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) \- .*?Logout from""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""", 
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]{1,2000})\s{0,100}(Juniper|PulseSecure):""",
    """\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]\s{1,100}(?:({user_email}[^@\s]{1,2000}@[^@\s\(]{1,2000})|({user}[^\(\s]{1,2000}))""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\(]{1,2000})|({user}[^\s\\]{1,2000}))\(({realm}[^\)]{1,2000})?""",
    """Logout from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```