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
      """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}""",
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """\(({process_id}\d{1,100}).*\)""",
      """({activity}A database location change) was detected from\s{1,100}\'({src_file_path}({src_file_dir}(?:[^";]{1,2000})?[\\\/;])?({src_file_name}[^\\\/";]{1,2000}?(\.({src_file_ext}[^\\\/\.;"]{1,2000}))))'\s{1,100}to\s{1,100}\'({file_path}({file_parent}(?:[^";]{1,2000})?[\\\/;])?({file_name}[^\\\/";]{1,2000}?(\.({file_ext}[^\\\/\.;"]{1,2000}))))\'\."""
    ]
    DupFields = [ "host->dest_host" ]
  

}
```