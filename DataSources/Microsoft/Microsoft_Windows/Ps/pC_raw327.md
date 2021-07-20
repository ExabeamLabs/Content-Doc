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
      """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}""",
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """\(({process_id}\d{1,100}).*\)""",
      """({activity}The database engine detached a database)\s{1,100}\(\d{1,100}
```