#### Parser Content
```Java
{
Name = raw-675
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-675"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "Pre-authentication failed:" ]
    Fields = [ 
      """({event_name}Pre-authentication failed)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({event_code}675)""",
      """rn=({record_id}\d+)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s+|\s*,\s*)({host}[\w.\-]+)""",
      """({host}[^\/\s]+)\/Security \(675\)""",
      """User Name:\s*({user}.+?)\s+User ID:\s*(\%\{)?({user_sid}[^\}\s]+)\}?""",
      """Service Name:\s*\w+\/(?=\w)({domain}.+?)\s+Pre-Authentication""",
      """Failure Code:\s*({result_code}[\w]+)""",
      """Client Address:\s*(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
    ]
  }
```