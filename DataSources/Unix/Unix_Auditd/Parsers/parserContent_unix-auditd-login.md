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
    """exabeam_host=({host}[^\s]+)""",
    """({time}\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})""",
    """msg=audit\(({time}\d{10})""",
    """\saddr=(?:\?|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]+))\s""",
    """acct="*({user}[^"=]+?)\s*(\w+=|")""", 
    """\sres=({outcome}[^']+)\'""",
    """\sses=({session_id}\S+?)\s*(\w+=|")""",
    """({event_code}ssh)""",
    """\spid=({process_id}\d+)""",
    """\suid=({user_id}\S+?)\s*(\w+=|")""",
    """auid=({account_used_id}\S+?)\s*(\w+=|")""",
    """exe="*({process_directory}[^"=]+?)\s*(\w+=|")""",
    """hostname="*(\?|({host}[^\s]+?))\s*(\w+=|")"""
  ]
  DupFields = [ "host->dest_host" ]
}
```