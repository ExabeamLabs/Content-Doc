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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}passwd:""",
    """\Wruser=({account}[^\s]{1,2000})""",
    """\Wuser=({user}[^\s]{1,2000})""",
    """({outcome}failure)""",
  ]


}
```