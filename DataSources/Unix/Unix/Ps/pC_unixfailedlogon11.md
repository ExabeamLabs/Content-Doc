#### Parser Content
```Java
{
Name = unix-failed-logon-11
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ sshd[""", """]: No authentication methods succeeded for user""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d(\.\S+)?\s({host}[^\s]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}(\.\S+)?\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}""",
    """No authentication methods succeeded for user ({user}[^""]{1,2000})"""
  ]


}
```