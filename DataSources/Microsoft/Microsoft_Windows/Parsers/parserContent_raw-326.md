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
      """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}""",
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """\(({process_id}\d{1,100}).*\)""",
      """({activity}The database engine attached a database)\s{1,100}\(\d{1,100}
```