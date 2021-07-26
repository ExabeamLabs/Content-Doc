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
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s{0,100}({host}[\w\-\.]{1,2000})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\].+?\[({resource}[^\]]{1,2000})\]""",
    """({event_code}Agent login succeeded) for ({user}[^",@\/]{1,2000})(?:@({domain}[^\/]{1,2000}))?.+? from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""", 
    """Agent login succeeded for (({domain}[^\\]{1,2000})\\+)?({user}[^\\\/\s\@",]{1,2000}) from """,
    """\(({realm}[^\)]{1,2000})\)\[REALM\]""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\(]{1,2000})|({user}[^\s\\]{1,2000}))\(({realm}[^\)]{1,2000})?""",
    """({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]
}
```