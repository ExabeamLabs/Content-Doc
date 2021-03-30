#### Parser Content
```Java
{
Name = unix-account-keyinit
  DataType = "unix-account-switch"
  Conditions = [ """[][][""", """ pam_keyinit(sudo""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sUser unknown:\s*(({domain}[^\\]+?)\\+)?({user}[^\\]+)\s*$""",
    """pam_keyinit\S*?:\s*({event_name}.*?change UID to ({account_used_id}\d+).*?)\s*$"""
  ]
}
unix-events = {
  Vendor = Unix
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """\[({src_ip}[a-fA-F\d.:]+)\]\[\d+\]\[\w+\]\[\]<\d+>\d+ ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+(\+|\-)\d\d:\d\d ({host}[\w.\-]+) ({event_code}\S+)""",
  ]

```