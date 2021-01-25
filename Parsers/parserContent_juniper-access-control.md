#### Parser Content
```Java
{
Name = juniper-access-control
  Vendor = Juniper Networks
  Lms = Splunk
  DataType = "access-control"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Agent login succeeded for" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s*({host}[\w\-\.]+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\].+?\[({resource}[^\]]+)\]""",
    """({event_code}Agent login succeeded) for ({user}[^",@\/]+)(?:@({domain}[^\/]+))?.+? from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Agent login succeeded for (({domain}[^\\]+)\\+)?({user}[^\\\/\s\@",]+) from """
    """\(({realm}[^\)]+)\)\[REALM\]""",
    """({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]
}
```