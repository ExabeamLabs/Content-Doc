#### Parser Content
```Java
{
Name = s-f5-vpn-p1
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""<CLIENT_ACCEPTED>""", """session_id=""", """ip="""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}([^\/\s]{1,2000}\/)?({host}[^\s]{1,2000}).+?user=({user}[^\s]{1,2000}).+?session_id=({session_id}[^\s]{1,2000})\sip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```