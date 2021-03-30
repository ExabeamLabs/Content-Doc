#### Parser Content
```Java
{
Name = unix-account-lockout
  DataType = "account-lockout"
  Conditions = [ """[][][""", """ pam_faillock(sshd:auth): User unknown: """ ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sUser unknown:\s*(({domain}[^\\]+?)\\+)?({user}[^\\]+?)\s*$""",
    """({auth_method}pam_faillock)"""
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