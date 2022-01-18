#### Parser Content
```Java
{
Name = s-4648-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-switch"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "明示的な資格情報を使用してログオンが試行されました。" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """ComputerName =({computer_name}[\w.\-]{1,2000})""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4648),""",
      """EventCode=({event_code}\w+)""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000

}
```