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
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}5157)""",
      """summary_windows_5157_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::({event_code}[^:::]{1,2000})?:::({host}[^:::]{1,2000})?:::({pid}[^:::]{1,2000})?:::({process}({directory}(?:.+?)?[\\\/])?({process_name}[^\\\/:::]{1,2000}))?:::({src_ip}[^:::]{1,2000})?:::({src_port}[^:::]{1,2000})?:::({dest_ip}[^:::]{1,2000})?:::({dest_port}[^:::]{1,2000})?:::({protocol}[^:::]{1,2000})?:::({event_name}[^:::]{1,2000})?:::([^:::]{1,2000})?:::({direction}[^:::]{1,2000})?:::([^:::]{1,2000})?:::({layer_name}[^:::]{1,2000})?""""
    ]
    DupFields = [ "host->local_asset", "directory->process_directory" ]
  }
```