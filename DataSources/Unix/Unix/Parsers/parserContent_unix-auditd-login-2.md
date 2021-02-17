#### Parser Content
```Java
{
Name = unix-auditd-login-2
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """type=USER_AUTH""","""PAM:authentication""","""terminal=""" ]
  Fields = [
    """,({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
    """\spid=({process_id}\d+)""",
    """\suid=({user_id}\d+)""",
    """auid=({account_used_id}\d+)""",
    """ses=({session_id}\d+)""",
    """acct="+({user}[^"]+)"+""",
    """exe="+({process_directory}[^"]+)"+""",
    """res=({outcome}[^']+)""",
    """\s*({host}[^\s]+)\sauditlog"""
 ]
}
```