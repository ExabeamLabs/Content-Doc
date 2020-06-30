#### Parser Content
```Java
{
Name = syslog-juniper-vpn-realm
  Vendor = Juniper Networks
  Lms = Syslog
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " PulseSecure:", " realm restrictions successfully passed" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """PulseSecure:\s+({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s+\-\s+[^\s]+\s+\-\s+\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """passed for ({user}[^\s\\\/]+)[\\\/]({domain}[^\s\\\/]+)\s*$""",
    """PulseSecure:.*?\[(127\.0\.0\.1|({src_ip}[a-fA-F:\d.]+))\]\s+(({domain}[^\\\/]+)[\\\/])?({user}[^\s\\\/]+)[\\\/]?\((?:unknown|({realm}[^\)]+))?""",
  ]
  DupFields = [ "host->dest_host" ]
}
```