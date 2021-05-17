#### Parser Content
```Java
{
Name = s-4769-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4769"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4769", "Kerberos サービス チケットが要求されました。" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4769,""",
      """ComputerName=({computer_name}[\w.\-]{1,2000})""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000}
```