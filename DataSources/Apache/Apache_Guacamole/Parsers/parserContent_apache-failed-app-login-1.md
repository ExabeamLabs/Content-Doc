#### Parser Content
```Java
{
Name = apache-failed-app-login-1
  Vendor = Apache
  Product = Apache Guacamole
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """auth.AuthenticationService -""", """] WARN """, """Authentication attempt from """, """failed"""]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Authentication attempt from \[({src_ip}[a-fA-F0-9\.:]+)\,\s({dest_ip}[a-fA-F0-9\.:]+)\]""",
    """for user "{1,20}({user}[^"]+)"{1,20} failed""",
    ]
}
```