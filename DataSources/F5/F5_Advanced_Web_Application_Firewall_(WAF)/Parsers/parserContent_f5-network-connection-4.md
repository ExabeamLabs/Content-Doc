#### Parser Content
```Java
{
Name = f5-network-connection-4
  Vendor = F5
  Product = F5 Advanced Web Application Firewall (WAF)
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ tmm""", """ SSL """, """SSL Handshake failed""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})""",
    """({event_name}SSL Handshake failed)""",
    """TCP ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100}) -> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100})"""
  ]
}
```