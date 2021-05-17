#### Parser Content
```Java
{
Name = s-windows-5140
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ "Exabeam Windows 5140", "summary_windows_5140_data" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}[+-]\d{1,100})""",
      """({event_code}5140)""",
      """({accesses}Read)""",
      """summary_windows_5140_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::({host}[^:::]{1,2000})?:::({logon_id}[^:::]{1,2000})?:::({user}[^:::]{1,2000})?:::({domain}[^:::]{1,2000})?:::({file_type}[^:::]{1,2000})?:::({src_ip}.+?)?:::({share_name}[^:::]{1,2000})?:::(?:\s{0,100}|({share_path}({d_parent}.*?)({d_name}[^\\]{1,2000}?))(\\+)?)?"""
    ]
      DupFields=[ "host->dest_host" ]
  }
```