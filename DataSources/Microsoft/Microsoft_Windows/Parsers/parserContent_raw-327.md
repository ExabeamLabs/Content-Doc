#### Parser Content
```Java
{
Name = raw-327
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "file-close" 
    Conditions = [ """Event ID: 327""","""The database engine detached a database""" ]
    Fields = [
      """ComputerName(:|=)\s*({host}[\w.-]+)\s+({process_name}[^\s]+)\s+""",
      """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s*({event_code}\d+)""",
      """\(({process_id}\d+).*\)""",
      """({activity}The database engine detached a database)\s+\(\d+,\s+({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))\)\."""
    ]
    DupFields = [ "host->dest_host" ]
  }
```