#### Parser Content
```Java
{
Name = unix-auth-failed
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ unix_chkpwd[""", """]: password check failed for """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s{1,100}""",
    """password check failed for user \(({user}[^\s\)]+)""",
  ]
}
```