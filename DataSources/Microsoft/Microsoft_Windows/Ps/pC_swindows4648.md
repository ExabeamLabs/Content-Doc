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
      """summary_windows_4648_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::(-|({host}[^:::]{1,2000}))?:::(-|({event_code}[^:::]{1,2000}))?:::(-|({user_sid}[^:::]{1,2000}))?:::(-|({user}[^:::]{1,2000}))?:::(-|({domain}[^:::]{1,2000}))?:::(-|({logon_id}[^:::]{1,2000}))?:::(-|({account}[^:::]{1,2000}))?:::(-|({account_domain}[^:::]{1,2000}))?:::(-|({dest_host}[^:::]{1,2000}))?:::(-|({process_id}[^:::]{1,2000}))?:::({process}({directory}(?:.+?)?[\\\/])?({process_name}[^\\\/:::]{1,2000}))?:::"""
    ]
      DupFields=[ "directory->process_directory" ]
  

}
```