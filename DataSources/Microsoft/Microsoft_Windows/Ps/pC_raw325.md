#### Parser Content
```Java
{
Name = raw-325
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "file-write" 
    Conditions = [ """Event ID: 325""","""The database engine created a new database""" ]
    Fields = [
      """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}""",
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """\(({process_id}\d{1,100}).*\)""",
      """({activity}The database engine created a new database)\s{1,100}\(\d{1,100

}
```