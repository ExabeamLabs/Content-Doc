#### Parser Content
```Java
{
Name = auditd-unix-process-created
  Vendor = Unix
  Product = Auditd
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """audispd""", """USER_CMD""", """ cmd=""" ]
  Fields = [
    """node=({host}[^\s\.]+)"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """uid=({user_id}[^\s]+)""",
    """auid=({account_used_id}[^\s]+)""",
    """pid=({process_id}[^\s]+)""",
    """cmd="({process}[^"]*)"""",
    """cmd="({process_directory}.+\/)({process_name}.+?)"""",
    """res=({outcome}[^\s'"]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```