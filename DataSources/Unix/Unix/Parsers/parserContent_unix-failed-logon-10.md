#### Parser Content
```Java
{
Name = unix-failed-logon-10
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ sshd[""", """]: Unable to negotiate """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}""",
    """Unable to negotiate with (({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
    """ port ({src_port}\d{1,100})({failure_reason}.*?)"""",
  ]
}
```