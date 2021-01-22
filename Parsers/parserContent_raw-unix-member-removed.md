#### Parser Content
```Java
{
Name = raw-unix-member-removed
  Vendor = Unix
  Lms = Direct
  DataType = "unix-member-removed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "removed by", "from group", "user", "gpasswd" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """user ({account_name}.+?) removed by ({user}.+?) from group ({group_name}.+?)\s*$""",
  ]
  DupFields=["host->dest_host"]
}
```