#### Parser Content
```Java
{
Name = unix-auth-event-2
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ httpd:""", """]: Login_Allowed - """, """apparently_via=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
    """httpd:\s{0,100}({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d(\.\S{1,2000})?\s({host}[\w\-.]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}(\.\S{1,2000})?\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}""",
    """ip=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
    """group=({group}[^\s"]{1,2000})""",
    """auth=({auth_method}[^\s]{1,2000})""",
    """\[(-|(({domain}[^\\\]]{1,2000})\\{1,25})?({user}[^\s\]]{1,2000}))\]:\s{0,100}({event_name}Login_Allowed)"""
  ]


}
```