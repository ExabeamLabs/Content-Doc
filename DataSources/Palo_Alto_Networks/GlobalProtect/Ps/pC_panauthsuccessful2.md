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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\d{1,100},({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}),""",
    """Client IP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """Server IP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    ]
}
```