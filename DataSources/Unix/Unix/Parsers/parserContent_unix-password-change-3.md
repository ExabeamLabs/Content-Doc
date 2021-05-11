#### Parser Content
```Java
{
Name = unix-password-change-3
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """couldn't change password for""", """keyring:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s{1,100}passwd:""",
    """couldn't change password for '({account}[^']+)""",
  ]
}
```