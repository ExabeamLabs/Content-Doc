#### Parser Content
```Java
{
Name = q-unix-as
  Vendor = Unix
  Lms = QRadar
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ "session opened for user", "(uid=", "sshd:", "_unix" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-.]+)\s+pam_unix""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+[\+\-]\d+:\d+)""",
    """session opened for user ({account}.+?) by""",
    """\(uid=({user_uid}\d+)\)""",
    """({host}[\w.\-]+) sshd ({logon_id}\d+) authpriv""",
    """sshd\[({logon_id}\d+)""",
    """\d\d:\d\d:\d\d ({host}[\w.\-]+)\s+""",
    """({event_code}ssh)""",
    """"host":"({host}[^"]+)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
  ]
  DupFields = [ "host->dest_host", "user_uid->user_id"]
}
```