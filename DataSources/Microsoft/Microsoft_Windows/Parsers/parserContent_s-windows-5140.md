#### Parser Content
```Java
{
Name = s-windows-5140
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 5140", "summary_windows_5140_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d+)""",
      """({event_code}5140)""",
      """({accesses}Read)""",
      """summary_windows_5140_data="+\d+:\d+:\d+\s*\d+-\d+-\d+:::({host}[^:::]+)?:::({logon_id}[^:::]+)?:::({user}[^:::]+)?:::({domain}[^:::]+)?:::({file_type}[^:::]+)?:::({src_ip}.+?)?:::({share_name}[^:::]+)?:::(?:\s*|({share_path}({d_parent}.*?)({d_name}[^\\]+?))(\\+)?)?"""
    ]
      DupFields=[ "host->dest_host" ]
  }
```