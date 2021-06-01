#### Parser Content
```Java
{
Name = apache-app-login-1
  Vendor = Apache
  Product = Apache Guacamole
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """auth.AuthenticationService - User""", """] INFO """, """successfully authenticated from """]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User "{1,20}({user}[^"]{1,2000})"{1,20} successfully authenticated from""",
    """successfully authenticated from\s\[({src_ip}[a-fA-F0-9\.:]{1,2000}),\s({dest_ip}[a-fA-F0-9\.:]{1,2000})\]""",
    ]
}
```