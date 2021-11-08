#### Parser Content
```Java
{
Name = unix-auditd-account-created-id
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "unix-account-created"
  TimeFormat = "epoch_sec"
  Conditions = [ """type=ADD_GROUP""","""op=add-group""","""res=success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """msg=audit\(({time}\d{1,100})\.\d{3}""",
    """\sacct="({account_name}[^"]{1,2000})"""",
    """\sses=({session_id}\d{1,100})""",
    """\spid=({process_id}\d{1,100})""",
  ]
}
```