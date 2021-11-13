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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}su:""",
    """\Wruser=({account}[^\s]{1,2000})""",
    """\Wuser=({user}[^\s]{1,2000})""",
    """({outcome}failure)""",
  ]


}
```