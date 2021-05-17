#### Parser Content
```Java
{
Name = unix-auth-failed-4
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """: expired password for user""", """sshd[""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]{1,2000})\s{1,100}sshd\[""",
    """expired password for user ({account}.+?) \(({failure_reason}.+?)\)""",
  ]
}
```