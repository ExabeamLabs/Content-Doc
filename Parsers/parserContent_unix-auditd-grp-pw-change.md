#### Parser Content
```Java
{
Name = unix-auditd-grp-pw-change
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=GRP_MGMT""","""op=changing-group-passwd""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """msg=audit\(({time}\d+)\.\d{3}""",
    """\sacct="({account_name}[^"]+)"""",
    """\sses=({session_id}\d+)""",
    """\spid=({process_id}\d+)""",
    """\sgrp="({group_name}[^"]+)"""",
  ]
  DupFields = ["group_name->group"]
}
```