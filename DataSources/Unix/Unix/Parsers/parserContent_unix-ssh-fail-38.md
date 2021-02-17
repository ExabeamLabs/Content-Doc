#### Parser Content
```Java
{
Name = unix-ssh-fail-38
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ssh""", """<38>""", """ Message forwarded from """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Message forwarded from (::ffff:)?({host}[^\s:]+)""",
    """({failure_reason}Invalid user) ({user}[^\s]+) from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """input_userauth_request: ({failure_reason}invalid user) ({user}[^\s]+)""",
    """({protocol}ssh(d)?)""",
    """failed login attempt for ({user}[^\s]+) from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Login restricted for ({user}[^\s:]+)""",
    """({failure_reason}There have been too many unsuccessful login attempts)"""
  ]
}
```