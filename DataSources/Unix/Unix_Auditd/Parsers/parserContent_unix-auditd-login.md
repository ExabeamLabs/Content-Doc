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
    """msg=audit\(({time}\d{10})""",
    """\saddr=(?:\?|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]+))\s""",
    """\sacct="({user}[^"]+)"""",
    """\sres=({outcome}[^']+)\'""",
    """\sses=({session_id}\d+)""",
    """({event_code}ssh)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```