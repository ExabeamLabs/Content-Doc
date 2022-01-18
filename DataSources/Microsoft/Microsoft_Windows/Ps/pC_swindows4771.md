#### Parser Content
```Java
{
Name = s-windows-4771
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4771"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 4771", "summary_windows_4771_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}4771)""",
      """summary_windows_4771_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::({host}[^:::]{1,2000})?:::({event_code}[^:::]{1,2000})?:::({user_sid}[^:::]{1,2000})?:::({domain}[^:::]{1,2000})?:::({dest_ip}[^:::]{1,2000})?:::([^:::]{1,2000}):::({result_code}[^:::]{1,2000})?:::({user}[^:::]{1,2000})?""""
    ]
    DupFields = ["host->dest_host"]
  

}
```