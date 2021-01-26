#### Parser Content
```Java
{
Name = unix-auditd-member-added-3
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "unix-member-added"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=USER_MGMT""","""op=add-user-to-shadow-group""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """msg=audit\(({time}\d+)\.\d{3}""",
    """\sacct="({account_name}[^"]+)"""",
    """\sauid="?({account_used_id}\d+)""",
    """\sgrp="({group_name}[^"]+)"""",
    """\suid=({user_id}\d+)""",
    """\sses=({session_id}\d+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```