#### Parser Content
```Java
{
Name = unix-auth-failed-4
  Vendor = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """: expired password for user""", """sshd[""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+sshd\[""",
    """expired password for user ({account}.+?) \(({failure_reason}.+?)\)""",
  ]
}
```