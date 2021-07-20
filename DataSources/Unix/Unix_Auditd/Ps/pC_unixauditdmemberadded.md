#### Parser Content
```Java
{
Name = unix-auditd-member-added
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "unix-member-added"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=USER_MGMT""","""op=add-user-to-group""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """msg=audit\(({time}\d{1,100})\.\d{3}""",
    """\sacct="({account_name}[^"]{1,2000})"""",
    """\sauid="?({account_used_id}\d{1,100})""",
    """\sgrp="({group_name}[^"]{1,2000})"""",
    """\suid=({user_id}\d{1,100})""",
    """\sses=({session_id}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```