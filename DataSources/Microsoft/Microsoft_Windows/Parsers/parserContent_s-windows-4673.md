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
      """summary_windows_4673_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]+))?:::(-|({event_code}[^:::]+))?:::(-|({outcome}[^:::]+))?:::(-|({process_directory}.+?))?:::(-|({process_name}.+?))?:::(-|({user}[^:::]+))?:::(-|({domain}[^:::]+))?:::(-|({logon_id}[^:::]+))?:::(-|({object_server}[^:::]+))?:::(-|({privileges}.+?))""""
    ]
    DupFields=[ "host->dest_host" ]
  }
```