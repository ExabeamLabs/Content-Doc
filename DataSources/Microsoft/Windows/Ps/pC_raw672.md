#### Parser Content
```Java
{
Name = raw-672
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-672"
  TimeFormat ="MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Name:", "Supplied Realm Name:", "krbtgt" ]
  Fields = [
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s{1,100}|\s{0,100},\s{0,100})({host}[\w.\-]{1,2000})""",
    """({event_code}672)""",
    """User Name:\s{0,100}({user}[^@\s]{1,2000})""",
    """Security(,|\srn=|\s{1,100})({record_id}\d{1,100})""",
    """Supplied Realm Name:\s{0,100}({domain}[^\s]{1,2000})\s""",
    """Client Address:\s{0,100}({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """Result Code:\s{0,100}({result_code}[\w\-]{1,2000})""",
    """User ID:\s{0,100}\%\{({user_sid}[^}]{1,2000})\}""",
  ]
}
```