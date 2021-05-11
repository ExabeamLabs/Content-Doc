#### Parser Content
```Java
{
Name = unix-failed-logon-3
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """sshd[""", """]: Failed password for """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^\=]+@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s{1,100}""",
    """Message forwarded from ({host}[^\s:]+)""",
    """({event_code}ssh)""",
    """Failed password for ({user}[^\s]+) from ({src_ip}[A-Fa-f:\d.]+)""",
    """ port ({src_port}\d{1,100})""",
  ]
}
```