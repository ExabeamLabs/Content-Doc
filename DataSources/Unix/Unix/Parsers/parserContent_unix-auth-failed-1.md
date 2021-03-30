#### Parser Content
```Java
{
Name = unix-auth-failed-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ su: pam_unix(su:auth)""", """authentication failure;""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+su:""",
    """\Wruser=({account}[^\s]+)""",
    """\Wuser=({user}[^\s]+)""",
    """({outcome}failure)""",
  ]
}
```