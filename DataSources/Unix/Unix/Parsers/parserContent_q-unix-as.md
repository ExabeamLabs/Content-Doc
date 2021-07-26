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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S+)""",
    """(::ffff:)?({host}[\w\-.]{1,2000})\s{1,100}pam_unix""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})""",
    """session opened for user ({account}.+?) by""",
    """\(uid=({user_uid}\d{1,100})\)""",
    """(::ffff:)?({host}[\w.\-]{1,2000}) sshd ({logon_id}\d{1,100}) authpriv""",
    """sshd\[({logon_id}\d{1,100})""",
    """\d\d:\d\d:\d\d (::ffff:)?({host}[\w.\-]{1,2000})\s{1,100}""",
    """({event_code}ssh)""",
    """"host":"(::ffff:)?({host}[^"]{1,2000})""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """\d\d:\d\d:\d\d (::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))"""
  ]
  DupFields = [ "user_uid->user_id"]
}
```