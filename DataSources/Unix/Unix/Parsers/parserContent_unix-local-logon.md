#### Parser Content
```Java
{
Name = unix-local-logon
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "local-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """systemd: Started Session""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s+systemd: Started Session""",
    """of user ({user}[^\s\.]+)""",
    """({event_code}Started Session)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```