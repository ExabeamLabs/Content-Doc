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
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s({host}[\w.-]{1,2000})\stype=USER_AUTH""",
    """({host}[\w\-.]{1,2000})\s{0,100}tag_audit_log:""",
    """\s{0,100}({host}[^\s]{1,2000})\s(auditlog|audispd)""",
    """({time}\d{2}\/\d{2}\/\d{4}\s{1,100}\d{2}:\d{2}:\d{2})""",
    """msg=audit\(({time}\d{10})""",
    """\spid=({process_id}\d{1,100})""",
    """\suid=({user_id}\S+?)\s{0,100}(\w+=|")""",
    """auid=({account_used_id}\S+?)\s{0,100}(\w+=|")""",
    """ses=({session_id}\S+?)\s{0,100}(\w+=|")""",
    """acct=\\?"{0,20}({user}[^"=\\]{1,2000}?)\\?\s{0,100}(\w+=|")""",
    """exe=\\?"{0,20}({process_directory}[^"=]{1,2000}?)\\?\s{0,100}(\w+=|")""",
    """res=\\?"{0,20}({outcome}[^'\s]{1,2000})""",
    """hostname="{0,20}(\?|({src_ip}(\d{1,3}\.){3}\d{1,3})|({src_host}[^\s]{1,2000}?))\s{0,100}(\w+=|")"""
 ]


}
```