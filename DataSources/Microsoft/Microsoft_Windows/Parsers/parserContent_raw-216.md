#### Parser Content
```Java
{
Name = raw-216
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "file-write" 
    Conditions = [ """Event ID: 216""","""A database location change was detected""" ]
    Fields = [
      """ComputerName(:|=)\s*({host}[\w.-]+)\s+({process_name}[^\s]+)\s+""",
      """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s*({event_code}\d+)""",
      """\(({process_id}\d+).*\)""",
      """({activity}A database location change) was detected from\s+\'({src_file_path}({src_file_dir}(?:[^";]+)?[\\\/;])?({src_file_name}[^\\\/";]+?(\.({src_file_ext}[^\\\/\.;"]+))))'\s+to\s+\'({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))\'\."""
    ]
    DupFields = [ "host->dest_host" ]
  }
```