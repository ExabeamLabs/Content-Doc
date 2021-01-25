#### Parser Content
```Java
{
Name = raw-unix-account-deleted
  Vendor = Unix
  Lms = Direct
  DataType = "unix-account-deleted"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "delete user", "userdel" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """delete user \'({target_user}[^']+)\'"""
  ]
  DupFields=["host->dest_host", "target_user->account_name"]
}
```