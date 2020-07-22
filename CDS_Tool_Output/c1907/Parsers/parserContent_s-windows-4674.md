#### Parser Content
```Java
{
Name = s-windows-4674
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4674", "summary_windows_4674_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d+)""",
      """({event_code}4764)""",
      """summary_windows_4674_data="+\d+:\d+:\d+\s*\d+-\d+-\d+:::(-|({host}[^:::]+))?:::(-|({event_code}[^:::]+))?:::(-|({outcome}[^:::]+))?:::(-|({process}.+?))?:::(-|({process_directory}.+?))?:::(-|({process_name}.+?))?:::(-|({user}[^:::]+))?:::(-|({domain}[^:::]+))?:::(-|({logon_id}[^:::]+))?:::(-|({object_server}[^:::]+))?:::(-|({object_type}[^:::]+))?:::(-|({object}.+?))?:::(-|({accesses}[^:::]+))?:::(-|({privileges}[^:::]+))?:::"""
    ]
      DupFields=[ "host->dest_host","process_directory->directory" ]
  }
```