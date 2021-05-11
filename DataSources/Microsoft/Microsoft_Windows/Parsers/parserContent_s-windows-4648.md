#### Parser Content
```Java
{
Name = s-windows-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4648", "summary_windows_4648_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}4748)""",
      """summary_windows_4648_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]+))?:::(-|({event_code}[^:::]+))?:::(-|({user_sid}[^:::]+))?:::(-|({user}[^:::]+))?:::(-|({domain}[^:::]+))?:::(-|({logon_id}[^:::]+))?:::(-|({account}[^:::]+))?:::(-|({account_domain}[^:::]+))?:::(-|({dest_host}[^:::]+))?:::(-|({process_id}[^:::]+))?:::({process}({directory}(?:.+?)?[\\\/])?({process_name}[^\\\/:::]+))?:::"""
    ]
      DupFields=[ "directory->process_directory" ]
  }
```