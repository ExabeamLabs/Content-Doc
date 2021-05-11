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
      """ComputerName(:|=)\s{0,100}({host}[\w.-]+)\s{1,100}({process_name}[^\s]+)\s{1,100}""",
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """\(({process_id}\d{1,100}).*\)""",
      """({activity}A database location change) was detected from\s{1,100}\'({src_file_path}({src_file_dir}(?:[^";]+)?[\\\/;])?({src_file_name}[^\\\/";]+?(\.({src_file_ext}[^\\\/\.;"]+))))'\s{1,100}to\s{1,100}\'({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))\'\."""
    ]
    DupFields = [ "host->dest_host" ]
  }
```