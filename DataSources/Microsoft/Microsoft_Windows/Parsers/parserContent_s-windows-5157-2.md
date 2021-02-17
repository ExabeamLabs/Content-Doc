#### Parser Content
```Java
{
Name = s-windows-5157-2
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "process-network-failed"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 5157", "summary_windows_5157_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d+)""",
      """({event_code}5157)""",
      """summary_windows_5157_data="+\d+:\d+:\d+\s*\d+-\d+-\d+:::({event_code}[^:::]+)?:::({host}[^:::]+)?:::({pid}[^:::]+)?:::({process}({directory}(?:.+?)?[\\\/])?({process_name}[^\\\/:::]+))?:::({src_ip}[^:::]+)?:::({src_port}[^:::]+)?:::({dest_ip}[^:::]+)?:::({dest_port}[^:::]+)?:::({protocol}[^:::]+)?:::({event_name}[^:::]+)?:::([^:::]+)?:::({direction}[^:::]+)?:::([^:::]+)?:::({layer_name}[^:::]+)?""""
    ]
    DupFields = [ "host->local_asset", "directory->process_directory" ]
  }
```