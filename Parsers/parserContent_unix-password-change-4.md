#### Parser Content
```Java
{
Name = unix-password-change-4
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """couldn't update the""", """keyring password:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+passwd:""",
    """couldn't update the '({account}[^']+)""",
    """keyring password: ({failure_reason}.+?)\s*$""",
  ]
}
```