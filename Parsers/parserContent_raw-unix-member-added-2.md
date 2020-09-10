#### Parser Content
```Java
{
Name = raw-unix-member-added-2
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-member-added"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "to group", "add", "usermod", """]:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """add \'({account_name}[^']+)\' to group \'({group_name}[^']+)\'""",
  ]
  DupFields=["host->dest_host"]
}
```