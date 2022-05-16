#### Parser Content
```Java
{
Name = unix-as
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """pam_unix(""", """session opened for user""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\S+)?)\s({host}({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
    """\[({src_ip}[a-fA-F\d.:]{1,2000})\]\[\d{1,100}\]\[\w+\]\[\]<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}(\+|\-)\d\d:\d\d ({host}({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000})) ({event_code}\S+)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,100}\d{1,2}\s{1,100}20\d{2}\s{1,100}\d{1,2}:\d{1,2}:\d{1,2})""",
    """\w+\s\d{1,100}\s\d\d:\d\d:\d\d(\.\S+)?\s({src_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})"""
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d(\.\S+)? ({host}({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000}))\s{1,100}.+?:\s{0,100}pam_unix""",
    """session opened for user ({account}.+?) by""",
    """\(uid=({user_uid}\d{1,100})\)""",
    """session opened for user \S+ by ({user}[^\("=,]{1,2000})""",
  ]
  DupFields = [ "user_uid->user_id"]


}
```