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
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}4764)""",
      """summary_windows_4674_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]{1,2000}))?:::(-|({event_code}[^:::]{1,2000}))?:::(-|({outcome}[^:::]{1,2000}))?:::(-|({process}.+?))?:::(-|({process_directory}.+?))?:::(-|({process_name}.+?))?:::(-|({user}[^:::]{1,2000}))?:::(-|({domain}[^:::]{1,2000}))?:::(-|({logon_id}[^:::]{1,2000}))?:::(-|({object_server}[^:::]{1,2000}))?:::(-|({object_type}[^:::]{1,2000}))?:::(-|({object}.+?))?:::(-|({accesses}[^:::]{1,2000}))?:::(-|({privileges}[^:::]{1,2000}))?:::"""
    ]
      DupFields=[ "host->dest_host","process_directory->directory" ]
  

}
```