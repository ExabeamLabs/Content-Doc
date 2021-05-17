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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}""",
    """Message forwarded from ({host}[^\s:]{1,2000})""",
    """({event_code}ssh)""",
    """failed login attempt for ({user}[^\s]{1,2000}) from (({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000}))\s""",
  ]
}
```