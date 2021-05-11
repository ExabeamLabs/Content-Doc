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
      """summary_windows_4625_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]+))?:::(-|({caller_user}[^:::]+))?:::(-|({caller_domain}[^:::]+))?:::(-|({logon_type}[^:::]+))?:::(-|({user_sid}[^:::]+))?:::(-|({user}[^:::]+))?:::(-|({domain}[^:::]+))?:::(-|({result_code}[^:::]+))?:::(-|({src_host_windows}[^:::]+))?:::(-|({src_host}[^:::]+))?:::(-|({src_ip}[^:::]+))?:::(-|({auth_process}[^:::]+))?:::(-|({auth_package}[^:::]+))?:::(-|({failure_reason}.+?))?""""
    ]
    DupFields = ["host->dest_host"]
  }
```