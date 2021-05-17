#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-resume
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "access-control"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Session resumed from user agent '""" ]
  Fields = [ 
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\sfw=({host}[\w\-\.]{1,2000})""",
    """({host}[\w\-\.]{1,2000})\s{1,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})""",
    """PulseSecure:\s{0,100}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]{1,2000})""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]{1,2000}))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?({user}[^\(]{1,2000})\(({realm}[^\)]{1,2000})?\)(\[({resource}[^\]]{1,2000})\])?""",
    """({event_code}Session resumed)""",
  ] 
  DupFields = ["user->account"]
}
```