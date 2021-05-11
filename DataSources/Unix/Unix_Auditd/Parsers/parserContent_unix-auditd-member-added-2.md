#### Parser Content
```Java
{
Name = unix-auditd-member-added-2
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "unix-member-added"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=USER_MGMT""","""op=add-to-shadow-group""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """msg=audit\(({time}\d{1,100})\.\d{3}""",
    """\sacct="({account_name}[^"]+)"""",
    """\sauid="?({account_used_id}\d{1,100})""",
    """\sgrp="({group_name}[^"]+)"""",
    """\suid=({user_id}\d{1,100})""",
    """\sses=({session_id}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```