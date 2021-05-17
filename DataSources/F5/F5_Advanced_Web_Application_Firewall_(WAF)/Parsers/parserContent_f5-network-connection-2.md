#### Parser Content
```Java
{
Name = f5-network-connection-2
  Vendor = F5
  Product = F5 Advanced Web Application Firewall (WAF)
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ tmm""", """ SSL """, """No shared ciphers between SSL peers""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})""",
    """peers ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.({src_port}\d{1,100}):({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.({dest_port}\d{1,100})""",
    """({event_name}No shared ciphers between SSL peers)"""
  ]
}
```