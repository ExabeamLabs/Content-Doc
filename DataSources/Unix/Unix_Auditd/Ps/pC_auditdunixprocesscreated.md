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
    """node=({host}[^\s\.]{1,2000})""",
    """\s({host}[\w\-.]{1,2000})\s{1,100}audispd:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\suid=({user_id}[^\s]{1,2000})""",
    """auid=({account_used_id}[^\s]{1,2000})""",
    """pid=({process_id}[^\s]{1,2000})""",
    """cmd=({process}[^\s]{1,2000})\s{1,100}[\w\=]{1,100}""",
    """cmd="?({process_directory}[^"]{0,2000}\/)({process_name}[^"]{1,2000}?)\s{0,100}("|\w{1,100}=|$)""",
    """res=({outcome}[^\s'"]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]


}
```