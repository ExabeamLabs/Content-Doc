#### Parser Content
```Java
{
Name = raw-675
    Vendor = Microsoft
    Product = Windows
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
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s{1,100}|\s{0,100},\s{0,100})({host}[\w.\-]{1,2000})""",
      """({host}[^\/\s]{1,2000})\/Security \(675\)""",
      """User Name:\s{0,100}({user}.+?)\s{1,100}User ID:\s{0,100}(\%\{)?({user_sid}[^\}\s]{1,2000})\}?""",
      """Service Name:\s{0,100}\w+\/(?=\w)({domain}.+?)\s{1,100}Pre-Authentication""",
      """Failure Code:\s{0,100}({result_code}[\w]{1,2000})""",
      """Client Address:\s{0,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
    ]
  }
```