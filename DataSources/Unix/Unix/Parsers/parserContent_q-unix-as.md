#### Parser Content
```Java
{
Name = q-unix-as
  Vendor = Unix
  Product = Unix
  Lms = QRadar
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "session opened for user", "(uid=", "sshd:", "_unix" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?(::ffff:)?({host}\S+)""",
    """(::ffff:)?({host}[\w\-.]+)\s+pam_unix""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+[\+\-]\d+:\d+)""",
    """session opened for user ({account}.+?) by""",
    """\(uid=({user_uid}\d+)\)""",
    """(::ffff:)?({host}[\w.\-]+) sshd ({logon_id}\d+) authpriv""",
    """sshd\[({logon_id}\d+)""",
    """\d\d:\d\d:\d\d (::ffff:)?({host}[\w.\-]+)\s+""",
    """({event_code}ssh)""",
    """"host":"(::ffff:)?({host}[^"]+)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """\d\d:\d\d:\d\d (::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))"""
  ]
  DupFields = [ "user_uid->user_id"]
}
```