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
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """uid=({user_id}[^\s]+)""",
    """auid=({account_used_id}[^\s]+)""",
    """pid=({process_id}[^\s]+)""",
    """cmd="?({process}[^"]*?)\s*("|\w+=|$)""",
    """res=({outcome}[^\s'"]+)"""
  ]
}
```