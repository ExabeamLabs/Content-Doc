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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """\sfw=({host}[\w\-\.]+)""",
    """({host}[\w\-\.]+)\s{1,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """PulseSecure:\s{0,100}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]+)""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]+)\\)?({user}[^\(]+)\(({realm}[^\)]+)?\)(\[({resource}[^\]]+)\])?""",
    """({event_code}Session resumed)""",
  ] 
  DupFields = ["user->account"]
}
```