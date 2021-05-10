#### Parser Content
```Java
{
Name = raw-unix-sudo
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """sudo:""", """; USER""","""; COMMAND""" ]
  Fields = [
    """({time}\w{3} \d{1,2}
```