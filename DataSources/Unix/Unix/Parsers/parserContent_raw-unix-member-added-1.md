#### Parser Content
```Java
{
Name = raw-unix-member-added-1
  Vendor = Unix
  Lms = Direct
  DataType = "unix-member-added"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "to group", "added by", "gpasswd" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """user ({account_name}.+?) added by ({user}.+?) to group ({group_name}.+?)\s*$""",
  ]
  DupFields=["host->dest_host"]
}
```