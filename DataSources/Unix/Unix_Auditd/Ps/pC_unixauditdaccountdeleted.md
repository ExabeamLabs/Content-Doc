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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """msg=audit\(({time}\d{1,100})\.\d{3}""",
    """\sauid=({account_used_id}\d{1,100})\s""",
    """\sid=({target_user_id}\d{1,100})""",
    """\suid=({user_id}\d{1,100})""",
    """\sses=({session_id}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```