#### Parser Content
```Java
{
Name = s-4624-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4624"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ "4624", "アカウントが正常にログオンしました。" ]
    Fields = [ """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4624,""",
      """ComputerName=({host}[\w.\-]{1,2000})""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000}
```