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
      """summary_windows_5140_data="{1,20}\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\d{1,100}-\d{1,100}-\d{1,100}:::({host}[^:::]+)?:::({logon_id}[^:::]+)?:::({user}[^:::]+)?:::({domain}[^:::]+)?:::({file_type}[^:::]+)?:::({src_ip}.+?)?:::({share_name}[^:::]+)?:::(?:\s{0,100}|({share_path}({d_parent}.*?)({d_name}[^\\]+?))(\\+)?)?"""
    ]
      DupFields=[ "host->dest_host" ]
  }
```