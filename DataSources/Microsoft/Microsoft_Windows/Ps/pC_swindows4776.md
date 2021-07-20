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
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}4776)""",
      """summary_windows_4776_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::({host}[^:::]{1,2000})?:::({event_code}[^:::]{1,2000})?:::({dest_host}[^:::]{1,2000})?:::({result_code}[^:::]{1,2000})?:::({user}[^:::]{1,2000})?:::([^:::]{1,2000}):::"""
    ]
  }
```