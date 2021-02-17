#### Parser Content
```Java
{
Name = f5-vpn-session-start
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490500:5:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d\s+({host}[^\s]+)\s([^\s]+\s)?[^\s]+\[\d+\]""",
    """"host":\{"name":"({host}[^"]+)""",
    """hostname="({host}[^"]+)""",
    """\s+01490500:5:.*?({session_id}[^\s:]+): New session""",
    """client IP ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```