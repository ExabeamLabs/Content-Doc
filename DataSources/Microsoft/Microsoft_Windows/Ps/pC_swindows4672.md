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
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}4762)""",
      """summary_windows_4672_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]{1,2000}))?:::(-|({event_code}[^:::]{1,2000}))?:::(-|({outcome}[^:::]{1,2000}))?:::(-|({user}[^:::]{1,2000}))?:::(-|({domain}[^:::]{1,2000}))?:::(-|({logon_id}[^:::]{1,2000}))?:::(-|([^:::]{1,2000}))?:::(-|([^:::]{1,2000}))?:::(-|([^:::]{1,2000}))?:::(-|({user_sid}[^:::]{1,2000}))?:::(-|({privileges}.+?))?""""
    ]
    DupFields=[ "host->dest_host" ]
  

}
```