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
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}4688)""",
      """summary_windows_4688_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::({host}[^:::]{1,2000})?:::({user_sid}[^:::]{1,2000})?:::({user}[^:::]{1,2000})?:::({domain}[^:::]{1,2000})?:::({logon_id}[^:::]{1,2000})?:::({process_guid}[^:::]{1,2000})?:::({process}({directory}(?:.+?)?[\\\/])?({process_name}[^\\\/:::]{1,2000}))?:::({command_line}[^:::]{1,2000})?:::({parent_process_guid}[^:::]{1,2000})?:::({activity_type}[^:::]{1,2000})?""""
    ]
    DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
  

}
```