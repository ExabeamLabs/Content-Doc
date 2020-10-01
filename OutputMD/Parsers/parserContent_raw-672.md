#### Parser Content
```Java
{
Name = raw-672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-672"
  TimeFormat ="MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Name:", "Supplied Realm Name:", "krbtgt" ]
  Fields = [
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """exabeam_source=({host}[A-Fa-f:\d.]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s+|\s*,\s*)({host}[\w.\-]+)""",
    """({event_code}672)""",
    """User Name:\s*({user}[^@\s]+)""",
    """Security(,|\srn=|\s+)({record_id}\d+)""",
    """Supplied Realm Name:\s*({domain}[^\s]+)\s""",
    """Client Address:\s*({dest_ip}[a-fA-F:\d.]+)""",
    """Result Code:\s*({result_code}[\w\-]+)""",
    """User ID:\s*\%\{({user_sid}[^}]+)\}""",
  ]
}
```