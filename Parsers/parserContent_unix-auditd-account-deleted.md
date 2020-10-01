#### Parser Content
```Java
{
Name = unix-auditd-account-deleted
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "unix-account-deleted"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=DEL_USER""","""op=delete-user""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """msg=audit\(({time}\d+)\.\d{3}""",
    """\sauid=({account_used_id}\d+)\s""",
    """\sid=({target_user_id}\d+)""",
    """\suid=({user_id}\d+)""",
    """\sses=({session_id}\d+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```