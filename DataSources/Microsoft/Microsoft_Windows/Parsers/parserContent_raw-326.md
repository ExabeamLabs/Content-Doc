#### Parser Content
```Java
{
Name = raw-326
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "file-read"
    Conditions = [ """Event ID: 326""","""The database engine attached a database""" ]
    Fields = [ 
      """ComputerName(:|=)\s*({host}[\w.-]+)\s+({process_name}[^\s]+)\s+""",
      """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s*({event_code}\d+)""",
      """\(({process_id}\d+).*\)""",
      """({activity}The database engine attached a database)\s+\(\d+,\s+({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))\)\."""
    ]
    DupFields = [ "host->dest_host" ]
  }
```