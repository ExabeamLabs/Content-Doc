#### Parser Content
```Java
{
Name = raw-unix-account-created
  Vendor = Unix
  Lms = Direct
  DataType = "unix-account-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "new user:", "useradd", "UID" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """new user: name=({account_name}[^,]+),""",
    """new user: .+?UID=({account_id}[^,]+),""",
  ]
  DupFields=["host->dest_host"]
}
```