#### Parser Content
```Java
{
Name = s-windows-4771
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4771"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4771", "summary_windows_4771_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d+)""",
      """({event_code}4771)""",
      """summary_windows_4771_data="+\d+:\d+:\d+\s*\d+-\d+-\d+:::({host}[^:::]+)?:::({event_code}[^:::]+)?:::({user_sid}[^:::]+)?:::({domain}[^:::]+)?:::({dest_ip}[^:::]+)?:::([^:::]+):::({result_code}[^:::]+)?:::({user}[^:::]+)?""""
    ]
  }
```