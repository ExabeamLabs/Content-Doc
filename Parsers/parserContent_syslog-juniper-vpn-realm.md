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
    """exabeam_host=({dest_host}[\w.\-]+)""",
    """PulseSecure:\s+({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s({dest_host}[\w.\-]+)\s+PulseSecure:""",
    """\d\d:\d\d:\d\d\s+\-\s+[^\s]+\s+\-\s+\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """passed for ({user}[^\s\\\/]+)[\\\/]({domain}[^\s\\\/]+)\s*$""",
    """PulseSecure:.*?\[(127\.0\.0\.1|({src_ip}[a-fA-F:\d.]+))\]\s+(({domain}[^\\\/]+)[\\\/])?({user}[^\s\\\/]+)[\\\/]?\((?:unknown|({realm}[^\)]+))?""",
  ]
  DupFields = [ "dest_host->host" ]
}
```