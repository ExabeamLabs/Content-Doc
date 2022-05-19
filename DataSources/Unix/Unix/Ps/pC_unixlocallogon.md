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
    """({host}[\w\-.]{1,2000})\s{1,100}systemd: Started Session""",
    """of user ({user}[^\s\.]{1,2000})""",
    """({event_code}Started Session)"""
  ]
  DupFields = [ "host->dest_host" ]


}
```