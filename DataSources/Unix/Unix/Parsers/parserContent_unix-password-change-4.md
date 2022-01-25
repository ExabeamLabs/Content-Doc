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
    """({host}[\w.\-]{1,2000})\s{1,100}passwd:""",
    """couldn't update the '({account}[^']{1,2000})""",
    """keyring password: ({failure_reason}.+?)\s{0,100}$""",
  ]
}
```