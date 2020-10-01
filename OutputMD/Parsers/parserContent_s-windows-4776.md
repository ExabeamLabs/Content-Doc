#### Parser Content
```Java
{
Name = s-windows-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4776", "summary_windows_4776_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d+)""",
      """({event_code}4776)""",
      """summary_windows_4776_data="+\d+:\d+:\d+\s*\d+-\d+-\d+:::({host}[^:::]+)?:::({event_code}[^:::]+)?:::({dest_host}[^:::]+)?:::({result_code}[^:::]+)?:::({user}[^:::]+)?:::([^:::]+):::"""
    ]
  }
```