#### Parser Content
```Java
{
Name = unix-auth-failed-3
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ passwd: pam_unix(""", """authentication failure;""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+passwd:""",
    """\Wruser=({account}[^\s]+)""",
    """\Wuser=({user}[^\s]+)""",
    """({outcome}failure)""",
  ]
}
```