#### Parser Content
```Java
{
Name = s-windows-4673
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4673", "summary_windows_4673_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}4763)""",
      """summary_windows_4673_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]{1,2000}))?:::(-|({event_code}[^:::]{1,2000}))?:::(-|({outcome}[^:::]{1,2000}))?:::(-|({process_directory}.+?))?:::(-|({process_name}.+?))?:::(-|({user}[^:::]{1,2000}))?:::(-|({domain}[^:::]{1,2000}))?:::(-|({logon_id}[^:::]{1,2000}))?:::(-|({object_server}[^:::]{1,2000}))?:::(-|({privileges}.+?))""""
    ]
    DupFields=[ "host->dest_host" ]
  

}
```