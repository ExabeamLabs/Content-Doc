#### Parser Content
```Java
{
Name = unix-auditd-account-created
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "unix-account-created"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=ADD_USER""","""op=add-user""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """msg=audit\(({time}\d{1,100})\.\d{3}""",
    """\sauid=({account_used_id}\d{1,100})\s""",
    """\sid=({account_id}\d{1,100})""",
    """\suid=({user_id}\d{1,100})""",
    """\sses=({session_id}\d{1,100})""",
    """\spid=({process_id}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host" ]
}
}
```