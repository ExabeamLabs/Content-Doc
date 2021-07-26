#### Parser Content
```Java
{
Name = raw-680
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-680"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "Logon attempt by:" ]
    Fields = [
      """({event_name}Logon attempt)""",
      """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
      """({event_code}680)""",
      """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s{1,100}|\s{0,100}
```