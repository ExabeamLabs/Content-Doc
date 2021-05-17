#### Parser Content
```Java
{
Name = unix-auditd-login
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=USER_AUTH""","""PAM:authentication""","""terminal=ssh""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({time}\d{2}\/\d{2}\/\d{4}\s{1,100}\d{2}:\d{2}:\d{2})""",
    """msg=audit\(({time}\d{10})""",
    """\saddr=(?:\?|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]{1,2000}))\s""",
    """acct="{0,20}({user}[^"=]{1,2000}?)\s{0,100}(\w+=|")""", 
    """\sres=({outcome}[^']{1,2000})\'""",
    """\sses=({session_id}\S+?)\s{0,100}(\w+=|")""",
    """({event_code}ssh)""",
    """\spid=({process_id}\d{1,100})""",
    """\suid=({user_id}\S+?)\s{0,100}(\w+=|")""",
    """auid=({account_used_id}\S+?)\s{0,100}(\w+=|")""",
    """exe="{0,20}({process_directory}[^"=]{1,2000}?)\s{0,100}(\w+=|")""",
    """hostname="{0,20}(\?|({host}[^\s]{1,2000}?))\s{0,100}(\w+=|")"""
  ]
  DupFields = [ "host->dest_host" ]
}
```