#### Parser Content
```Java
{
Name = f5-network-connection-6
  Vendor = F5
  Product = F5 Advanced Web Application Firewall (WAF)
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """HTTP_REQUEST:CONNECT""", """Connection Response to Client""", """VIRTUAL_SERVER:""" ]
  Fields = [
    """(?i:Date):\[({time}\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|-)\d{4})""",
    """\d\d:\d\d:\d\d ({host}[\w.-]{1,2000})""",
    """Client:({src_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """POOL_MEMBER:({dest_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """SERVER_PORT:({dest_port}\d{1,5})""",
    """({event_name}Connection Response to Client)""",
    """({protocol}HTTP\/\S+?)\s"""
  ]


}
```