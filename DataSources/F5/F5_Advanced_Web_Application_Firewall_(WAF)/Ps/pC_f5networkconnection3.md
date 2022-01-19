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
    """({event_name}Connection error: ssl_passthru)""",
    """warning[^->]{1,2000}\s{1,100}({src_ip}[A-Fa-f\d\.:]{1,2000}):({src_port}\d{1,100}) -> ({dest_ip}[A-Fa-f\d\.:]{1,2000}):({dest_port}\d{1,100})""",
    """({protocol}SSL)"""
  ]


}
```