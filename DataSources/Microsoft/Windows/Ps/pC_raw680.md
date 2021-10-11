#### Parser Content
```Java
{
Name = raw-680
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-680"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "Logon attempt by:" ]
    Fields = [
      """({event_name}Logon attempt)""",
      """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
      """({event_code}680)""",
      """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s{1,100}|\s{0,100},\s{0,100})({host}[\w\.\-]{1,2000})""",
      """Source Workstation:\s{1,100}(\\+)?({dest_host}[^\s.]{1,2000})[^\s]{0,2000}.+Error Code:\s{1,100}({result_code}[^\s]{1,2000})""",
      """Logon (?:a|A)ccount:\s{1,100}({user}[^@]{1,2000}?)(?:@({domain}[^\s]{1,2000}))?\s{1,100}Source""",
      """(Information|Audit Success|Success Audit|Audit Failure|Failure Audit)\s{1,100}[^\s.]{1,2000}\.({domain}[^\s.]{1,2000})""",
      """(?:Success|Audit)\s{1,100}\w+\s{1,100}[^\s.]{1,2000}(\.({domain}[^\s.]{1,2000})[^\s]{0,2000})"""
    ]
  }
```