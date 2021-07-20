#### Parser Content
```Java
{
Name = raw-unix-account-deleted
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-deleted"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "delete user", "userdel" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """delete user \'({target_user}[^']{1,2000})\'"""
  ]
  DupFields=["host->dest_host", "target_user->account_name"]
}
```