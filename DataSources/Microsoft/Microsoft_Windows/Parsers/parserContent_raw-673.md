#### Parser Content
```Java
{
Name = raw-673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-673"
  TimeFormat ="MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Ticket Request:", "Ticket Options:" ]
  Fields = [
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """({event_code}673)""",
    """exabeam_source=({host}[A-Fa-f:\d.]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s*,\s*({host}[^,]+)""",
    """Security(,|\srn=|\s+)({record_id}\d+)""",
    """User Name:\s*({user}[^@\s]+)""",
    """User Domain:\s*({domain}[^\s]+)\s""",
    """Client Address:\s*({src_ip}[a-fA-F:\d.]+)""",
    """Service Name:\s*({dest_host}\S+\$)\s""",
    """Service Name:\s*({service_name}\S+)""",
    """Failure Code:\s*({result_code}[\w\-]+)""",
    """Ticket Options:\s*({ticket_options}[^\s]+)""",
    """Ticket Encryption Type:\s*({ticket_encryption_type}[^\s]+)"""
  ]
}
```