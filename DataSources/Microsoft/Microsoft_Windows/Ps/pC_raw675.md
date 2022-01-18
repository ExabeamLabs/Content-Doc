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
      """rn=({record_id}\d{1,100})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s{1,100}|\s{0,100

}
```