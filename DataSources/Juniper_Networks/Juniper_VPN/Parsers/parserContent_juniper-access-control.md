#### Parser Content
```Java
{
Name = juniper-access-control
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Splunk
  DataType = "access-control"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Agent login succeeded for" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s{0,100}({host}[\w\-\.]+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\].+?\[({resource}[^\]]+)\]""",
    """({event_code}Agent login succeeded) for ({user}[^",@\/]+)(?:@({domain}[^\/]+))?.+? from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""", 
    """Agent login succeeded for (({domain}[^\\]+)\\+)?({user}[^\\\/\s\@",]+) from """,
    """\(({realm}[^\)]+)\)\[REALM\]""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\(]+)|({user}[^\s\\]+))\(({realm}[^\)]+)?""",
    """({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]
}
```