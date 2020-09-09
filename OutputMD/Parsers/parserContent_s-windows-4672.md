#### Parser Content
```Java
{
Name = s-windows-4672
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4672", "summary_windows_4672_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d+)""",
      """({event_code}4762)""",
      """summary_windows_4672_data="+\d+:\d+:\d+\s*\d+-\d+-\d+:::(-|({host}[^:::]+))?:::(-|({event_code}[^:::]+))?:::(-|({outcome}[^:::]+))?:::(-|({user}[^:::]+))?:::(-|({domain}[^:::]+))?:::(-|({logon_id}[^:::]+))?:::(-|([^:::]+))?:::(-|([^:::]+))?:::(-|([^:::]+))?:::(-|({user_sid}[^:::]+))?:::(-|({privileges}.+?))?""""
    ]
    DupFields=[ "host->dest_host" ]
  }
```