#### Parser Content
```Java
{
Name = unix-as
  Vendor = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """pam_unix(""", """session opened for user""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\[({src_ip}[a-fA-F\d.:]+)\]\[\d+\]\[\w+\]\[\]<\d+>\d+ ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+(\+|\-)\d\d:\d\d ({host}[\w.\-]+) ({event_code}\S+)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+20\d{2}\s+\d{1,2}:\d{1,2}:\d{1,2})""",
    """\w+\s\d+\s\d\d:\d\d:\d\d\s({src_ip}\d+\.\d+\.\d+\.\d+)"""
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\w+\s+\d+ \d\d:\d\d:\d\d ({host}[\w.\-]+).+?:\s*pam_unix""",
    """session opened for user ({account}.+?) by""",
    """\(uid=({user_uid}\d+)\)""",
  ]
  DupFields = [ "host->dest_host", "user_uid->user_id"]
}
```