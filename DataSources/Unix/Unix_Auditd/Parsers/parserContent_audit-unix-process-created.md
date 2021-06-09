#### Parser Content
```Java
{
Name = audit-unix-process-created
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """audit""", """USER_CMD""", """ cmd=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000})\s{0,100}tag_audit_log:""",
    """msg=audit\(({time}\d{10})""",
    """uid=({user_id}[^\s]{1,2000})""",
    """auid=({account_used_id}[^\s]{1,2000})""",
    """pid=({process_id}[^\s]{1,2000})""",
    """cmd="?({process}[^"]{0,2000}?)\s{0,100}("|\w+=|$)""",
    """res=({outcome}[^\s'"]{1,2000})"""
  ]
}
```