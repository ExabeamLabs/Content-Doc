#### Parser Content
```Java
{
Name = pan-auth-successful-2
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """panorama-auth-success""", """,SYSTEM,tls,""" ]
  Fields = [
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+\d+,({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+),""",
    """Client IP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """Server IP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    ]
}
```