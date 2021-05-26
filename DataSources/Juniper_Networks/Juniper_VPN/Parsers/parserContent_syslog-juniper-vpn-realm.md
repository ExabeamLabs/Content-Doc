#### Parser Content
```Java
{
Name = syslog-juniper-vpn-realm
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Syslog
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " PulseSecure:", " realm restrictions successfully passed" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """PulseSecure:\s{1,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s{1,100}\-\s{1,100}[^\s]{1,2000}\s{1,100}\-\s{1,100}\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})""",
    """passed for ({user}[^\s\\\/]{1,2000})[\\\/]({domain}[^\s\\\/]{1,2000})\s{0,100}$""",
    """PulseSecure:.*?\[(127\.0\.0\.1|({src_ip}[a-fA-F:\d.]{1,2000}))\]\s{1,100}(({domain}[^\\\/]{1,2000})[\\\/])?({user}[^\s\\\/]{1,2000})[\\\/]?\((?:unknown|({realm}[^\)]{1,2000}))?""",
  ]
  DupFields = [ "host->dest_host" ]
}
```