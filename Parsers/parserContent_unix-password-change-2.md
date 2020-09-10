#### Parser Content
```Java
{
Name = unix-password-change-2
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """changed password expiry for""", """chage[""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+chage\[""",
    """changed password expiry for ({account}\S+)""",
  ]
}
```