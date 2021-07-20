#### Parser Content
```Java
{
Name = s-windows-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = ["Exabeam Windows 4625", "summary_windows_4625_data="]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",    
      """({event_code}4625)""",
      """summary_windows_4625_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]{1,2000}))?:::(-|({caller_user}[^:::]{1,2000}))?:::(-|({caller_domain}[^:::]{1,2000}))?:::(-|({logon_type}[^:::]{1,2000}))?:::(-|({user_sid}[^:::]{1,2000}))?:::(-|({user}[^:::]{1,2000}))?:::(-|({domain}[^:::]{1,2000}))?:::(-|({result_code}[^:::]{1,2000}))?:::(-|({src_host_windows}[^:::]{1,2000}))?:::(-|({src_host}[^:::]{1,2000}))?:::(-|({src_ip}[^:::]{1,2000}))?:::(-|({auth_process}[^:::]{1,2000}))?:::(-|({auth_package}[^:::]{1,2000}))?:::(-|({failure_reason}.+?))?""""
    ]
    DupFields = ["host->dest_host"]
  }
```