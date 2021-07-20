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
    """\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s([^\s]{1,2000}\s)?[^\s]{1,2000}\[\d{1,100}\]""",
    """"host":\{"name":"({host}[^"]{1,2000})""",
    """hostname="({host}[^"]{1,2000})""",
    """\s{1,100}01490500:5:.*?({session_id}[^\s:]{1,2000}): New session""",
    """client IP ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```