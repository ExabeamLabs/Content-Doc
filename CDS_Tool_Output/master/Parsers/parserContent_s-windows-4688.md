#### Parser Content
```Java
{
Name = s-windows-4688
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4688", "summary_windows_4688_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d+)""",
      """({event_code}4688)""",
      """summary_windows_4688_data="+\d+:\d+:\d+\s*\d+-\d+-\d+:::({host}[^:::]+)?:::({user_sid}[^:::]+)?:::({user}[^:::]+)?:::({domain}[^:::]+)?:::({logon_id}[^:::]+)?:::({process_guid}[^:::]+)?:::({process}({directory}(?:.+?)?[\\\/])?({process_name}[^\\\/:::]+))?:::({command_line}[^:::]+)?:::({parent_process_guid}[^:::]+)?:::({activity_type}[^:::]+)?""""
    ]
    DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
  }
```