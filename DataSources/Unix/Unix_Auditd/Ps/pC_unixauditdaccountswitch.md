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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{0,100}tag_audit_log:""",
    """msg=audit\(({time}\d{1,100})\.\d{3}""",
    """\sacct="({account}[^"]{1,2000})"""",
    """\sauid="?({account_used_id}\d{1,100})""",
    """\suid=({user_id}\d{1,100})""",
    """\sses=({session_id}\d{1,100})""",
    """UID="{0,20}({user}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```