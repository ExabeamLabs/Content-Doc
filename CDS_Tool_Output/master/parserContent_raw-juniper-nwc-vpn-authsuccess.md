#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-authsuccess
  Vendor = Juniper Networks
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  " PulseSecure:", """ authentication successful for """ ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sfw=({host}[\w\-\.]+)""",
    """({host}[\w\-\.]+)\s+(Juniper|PulseSecure):""",
    """(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s+(Juniper|PulseSecure):""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@]+@[^@(]+)|({user}[^\(]+))\(({realm}[^\)]+)?\)""",
    """authentication successful for\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@\s\/]+@[^@\s\/]+)|({user}[^\/]+))(\/({realm}.+?))\s+from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s({host}[\w\-.]+)\s+\S+\s+PulseSecure:""",
    """PulseSecure:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}(?!ive)[\w\-.]+)""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
    """user=(({user_email}[^@\s\/]+@[^@\s\/]+)|({user}[^\/\s]+))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```