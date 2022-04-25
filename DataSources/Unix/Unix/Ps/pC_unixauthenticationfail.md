#### Parser Content
```Java
{
Name = unix-authentication-fail
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ httpd:""", """AD authentication for user""", """failed""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """@timestamp":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
    """\d\d:\d\d:\d\d(\.\S+)?\s({host}[^\s]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}(\.\S+)?\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}(\.\S+)?\s{1,100}[A-Fa-f:\d\.]{1,2000}\s\w{1,2000}:\s{0,100}({host}[\w\-]{1,2000})""",
    """({event_name}AD authentication) for user ({user}[^\s]{1,2000}) ({outcome}failed)"""
  ]


}
```