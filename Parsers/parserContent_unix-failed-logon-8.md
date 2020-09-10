#### Parser Content
```Java
{
Name = unix-failed-logon-8
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ssh: failed login attempt for """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+""",
    """Message forwarded from ({host}[^\s:]+)""",
    """({event_code}ssh)""",
    """failed login attempt for ({user}[^\s]+) from (({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+))\s""",
  ]
}
```