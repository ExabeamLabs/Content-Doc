#### Parser Content
```Java
{
Name = raw-unix-member-removed
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-member-removed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """removed by""", """from group""", """user""", """gpasswd""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\d\d:\d\d:\d\d(\.\S+)? ({host}[\w.\-]{1,2000})\sgpasswd""",
    """user ({account_name}.+?) removed by ({user}.+?) from group ({group_name}.+?)\s{0,100}$""",
  ]
  DupFields=["host->dest_host"]


}
```