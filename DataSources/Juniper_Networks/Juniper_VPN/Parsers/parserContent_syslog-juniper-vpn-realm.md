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
    """exabeam_host=({host}[\w.\-]+)""",
    """PulseSecure:\s{1,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s{1,100}\-\s{1,100}[^\s]+\s{1,100}\-\s{1,100}\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """passed for ({user}[^\s\\\/]+)[\\\/]({domain}[^\s\\\/]+)\s{0,100}$""",
    """PulseSecure:.*?\[(127\.0\.0\.1|({src_ip}[a-fA-F:\d.]+))\]\s{1,100}(({domain}[^\\\/]+)[\\\/])?({user}[^\s\\\/]+)[\\\/]?\((?:unknown|({realm}[^\)]+))?""",
  ]
  DupFields = [ "host->dest_host" ]
}
```