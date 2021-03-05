#### Parser Content
```Java
{
Name = auditd-unix-process-created
  Vendor = Unix
  Product = Auditd
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """audispd""", """USER_CMD""", """ cmd=""" ]
  Fields = [
    """node=({host}[^\s\.]+)""",
    """\s({host}[\w\-.]+)\s+audispd:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """uid=({user_id}[^\s]+)""",
    """auid=({account_used_id}[^\s]+)""",
    """pid=({process_id}[^\s]+)""",
    """cmd="?({process}[^"]*?)\s*("|\w+=|$)""",
    """cmd="?({process_directory}[^"]*\/)({process_name}[^"]+?)\s*("|\w+=|$)""",
    """res=({outcome}[^\s'"]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```