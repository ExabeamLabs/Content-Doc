#### Parser Content
```Java
{
Name = unix-auditd-account-switch
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=USER_START""","""op=PAM:session_open""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """msg=audit\(({time}\d+)\.\d{3}""",
    """\sacct="({account}[^"]+)"""",
    """\sauid="?({account_used_id}\d+)""",
    """\suid=({user_id}\d+)""",
    """\sses=({session_id}\d+)""",
    """UID="*({user}[^"]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```