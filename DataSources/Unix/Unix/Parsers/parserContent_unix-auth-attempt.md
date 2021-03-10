#### Parser Content
```Java
{
Name = unix-auth-attempt
  Vendor = Unix
  Lms = Direct
  DataType = "authentication-attempt"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """pam_unix(sshd:auth): check pass;""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+sshd\[""",
    """check pass; user (unknown|({user}\S+))""",
  ]
}
```