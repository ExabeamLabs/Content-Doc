#### Parser Content
```Java
{
Name = f5-network-connection-3
  Vendor = F5
  Product = F5 Advanced Web Application Firewall (WAF)
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ tmm""", """ SSL """, """Connection error: ssl_passthru""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})""",
    """({event_name}Connection error: ssl_passthru)"""
  ]
}
```