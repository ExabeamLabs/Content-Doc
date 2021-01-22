#### Parser Content
```Java
{
Name = raw-unix-su
  Vendor = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "session opened for user","su:", """(uid=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+)\s+su:""",
    """({event_code}su):.+?for user ({account}[^\s]+) by ({user}[\w\.]+)?\(uid=({user_uid}\d+)\)"""
  ]
DupFields=["host->dest_host"]
}
```