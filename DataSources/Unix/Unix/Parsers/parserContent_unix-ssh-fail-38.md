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
    """\ssshd\[[^:]{1,100}:\s{1,100}({failure_reason}[^=]+?)\s{1,100}from(\s{1,100}user\s{1,100}({user}[^\s]+))?\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}port\s{1,100}({src_port}\d{1,100})""",
    """({failure_reason}Invalid user) ({user}[^\s]+) from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """input_userauth_request: ({failure_reason}invalid user) ({user}[^\s]+)""",
    """({protocol}ssh(d)?)""",
    """failed login attempt for ({user}[^\s]+) from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Login restricted for ({user}[^\s:]+)""",
    """({failure_reason}There have been too many unsuccessful login attempts)"""
  ]
}
```