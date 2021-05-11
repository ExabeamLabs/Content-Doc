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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s{1,100}passwd:""",
    """\Wruser=({account}[^\s]+)""",
    """\Wuser=({user}[^\s]+)""",
    """({outcome}failure)""",
  ]
}
```