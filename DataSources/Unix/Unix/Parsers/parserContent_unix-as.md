#### Parser Content
```Java
{
Name = unix-as
  Vendor = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """pam_unix(""", """session opened for user""" ]
  Fields = [
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\w+\s+\d+ \d\d:\d\d:\d\d ({host}[\w.\-]+).+?:\s*pam_unix""",
    """session opened for user ({account}.+?) by""",
    """\(uid=({user_uid}\d+)\)""",
  ]
  DupFields = [ "host->dest_host", "user_uid->user_id"]
}
```