#### Parser Content
```Java
{
Name = s-4770-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4770"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4770", "Kerberos サービス チケットが更新されました。", "アカウント名:" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4770,""",
      """ComputerName =({computer_name}[\w.\-]{1,2000})""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000

}
```