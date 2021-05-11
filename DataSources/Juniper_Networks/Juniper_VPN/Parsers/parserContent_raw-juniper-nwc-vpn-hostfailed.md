#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-hostfailed
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Host Checker policy """, """ failed on host """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """\sfw=({host}[\w\-\.]+)""",
    """(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[(127\.0\.0\.1|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\]\s{1,100}(({domain}[^\\\s\(]+)\\)?({user}[^\\\s\(]+)\(({realm}[^\)]+)?\)""",
    """({host}[\w\-.]+)\s{1,100}\S+\s{1,100}PulseSecure:""",
    """({host}[\w\-\.]+)\s{1,100}(Juniper|PulseSecure):""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """PulseSecure:.*?\[(127\.0\.0\.1|({src_ip}[a-fA-F:\d.]+))\]\s{1,100}(({domain}[^\\]+)\\)?({user}[^\s]+)\(({realm}[^\)]+)?""",
    """ for user '(({domain}[^\\]+)\\)?({user}.+?)' reason '({failure_reason}[^';]+).*?'""",
    """({failure_reason}Host Checker policy '.+?' failed on host '?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]+?))'?)"""   
    """({failure_reason}Host Checker policy '.+?' failed on host '(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))' .*? for user '.+?')"""   
  ]
  DupFields = [ "host->dest_host" ]
}
```