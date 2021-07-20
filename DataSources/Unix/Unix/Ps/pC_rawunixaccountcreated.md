#### Parser Content
```Java
{
Name = raw-unix-account-created
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "new user:", "useradd", "UID" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """new user: name=({account_name}[^,]{1,2000}),""",
    """new user: .+?UID=({account_id}[^,]{1,2000}),""",
  ]
  DupFields=["host->dest_host"]
}
```