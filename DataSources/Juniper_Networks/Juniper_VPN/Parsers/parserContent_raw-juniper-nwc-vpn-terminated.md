#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-terminated
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Session for user """, """ on host """, """ has been terminated.""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\sfw=({host}[\w\-\.]{1,2000})""",
    """({host}[\w\-\.]{1,2000})\s{1,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]{1,2000})""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]{1,2000}))\s{1,100}(Juniper|PulseSecure):""",
    """Session for user\s{1,100}(({domain}[^\\]{1,2000})\\)?({user}.+?)\s{1,100}on host ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) has been terminated""",
  ]
}
```