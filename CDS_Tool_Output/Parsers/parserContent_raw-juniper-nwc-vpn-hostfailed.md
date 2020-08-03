#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-hostfailed
  Vendor = Juniper Networks
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Host Checker policy """, """ failed on host """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sfw=({host}[\w\-\.]+)""",
    """({host}[\w\-\.]+)\s+(Juniper|PulseSecure):""",
    """(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s+(Juniper|PulseSecure):""",
    """\- \[(127\.0\.0\.1|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\]\s+(({domain}[^\\\s\(]+)\\)?({user}[^\\\s\(]+)\(({realm}[^\)]+)?\)""",
    """({host}[\w\-.]+)\s+\S+\s+PulseSecure:""",
    """PulseSecure:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """PulseSecure:.*?\[(127\.0\.0\.1|({src_ip}[a-fA-F:\d.]+))\]\s+(({domain}[^\\]+)\\)?({user}[^\s]+)\(({realm}[^\)]+)?""",
    """ for user '(({domain}[^\\]+)\\)?({user}.+?)' reason '({failure_reason}[^';]+).*?'""",
    """({failure_reason}Host Checker policy '.+?' failed on host '?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]+?))'?)"""   
    """({failure_reason}Host Checker policy '.+?' failed on host '(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))' .*? for user '.+?')"""   
  ]
  DupFields = [ "host->dest_host" ]
}
```