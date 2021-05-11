#### Parser Content
```Java
{
Name = unix-password-change-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """changed password for""", """passwd:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s{1,100}passwd:""",
    """changed password for '({account}[^']+)'""",
  ]
}
```