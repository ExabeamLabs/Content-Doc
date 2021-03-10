#### Parser Content
```Java
{
Name = unix-password-change-3
  Vendor = Unix
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """couldn't change password for""", """keyring:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+passwd:""",
    """couldn't change password for '({account}[^']+)""",
  ]
}
```