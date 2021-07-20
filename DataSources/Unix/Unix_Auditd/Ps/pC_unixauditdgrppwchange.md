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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """msg=audit\(({time}\d{1,100})\.\d{3}""",
    """\sacct="({account_name}[^"]{1,2000})"""",
    """\sses=({session_id}\d{1,100})""",
    """\spid=({process_id}\d{1,100})""",
    """\sgrp="({group_name}[^"]{1,2000})"""",
  ]
  DupFields = ["group_name->group"]
}
```