#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-terminated
  Vendor = Juniper Networks
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Session for user """, """ on host """, """ has been terminated.""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\sfw=({host}[\w\-\.]+)""",
    """({host}[\w\-\.]+)\s+(Juniper|PulseSecure):""",
    """PulseSecure:\s*\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s+\-\s+({dest_host}[\w\-.]+)""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s+(Juniper|PulseSecure):""",
    """Session for user\s+(({domain}[^\\]+)\\)?({user}.+?)\s+on host ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) has been terminated""",
  ]
}
```