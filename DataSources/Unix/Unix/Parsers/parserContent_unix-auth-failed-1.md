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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s{1,100}su:""",
    """\Wruser=({account}[^\s]+)""",
    """\Wuser=({user}[^\s]+)""",
    """({outcome}failure)""",
  ]
}
```