#### Parser Content
```Java
{
Name = syslog-ssomgr-app-activity
  Vendor = Kemp
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """ssomgr: SSO-auth-token reused""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\s({host}[\w\-\.]+)\s+\S+\s+\-\s+ssomgr:""",
    """\[host=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\[user=(({domain}[^\\]+)\\)?({user}[^\]]+)\]""",
    """\[user=({user_email}[^@]+@[^@\]\s]+)\]""",
    """\[user=({user}[^@]+@[^@\]\s]+)\]""",
    """\sssomgr:\s*({activity}.+?)\s*\["""
  ]
}
```