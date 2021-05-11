#### Parser Content
```Java
{
Name = auditd-unix-process-created
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """audispd""", """USER_CMD""", """ cmd=""" ]
  Fields = [
    """node=({host}[^\s\.]+)""",
    """\s({host}[\w\-.]+)\s{1,100}audispd:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """uid=({user_id}[^\s]+)""",
    """auid=({account_used_id}[^\s]+)""",
    """pid=({process_id}[^\s]+)""",
    """cmd="?({process}[^"]*?)\s{0,100}("|\w+=|$)""",
    """cmd="?({process_directory}[^"]*\/)({process_name}[^"]+?)\s{0,100}("|\w+=|$)""",
    """res=({outcome}[^\s'"]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```