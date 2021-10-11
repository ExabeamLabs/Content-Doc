#### Parser Content
```Java
{
Name = raw-673
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-673"
  TimeFormat ="MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Ticket Request:", "Ticket Options:" ]
  Fields = [
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """({event_code}673)""",
    """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100},\s{0,100}({host}[^,]{1,2000})""",
    """Security(,|\srn=|\s{1,100})({record_id}\d{1,100})""",
    """User Name:\s{0,100}({user}[^@\s]{1,2000})""",
    """User Domain:\s{0,100}({domain}[^\s]{1,2000})\s""",
    """Client Address:\s{0,100}({src_ip}[a-fA-F:\d.]{1,2000})""",
    """Service Name:\s{0,100}({dest_host}\S+\$)\s""",
    """Service Name:\s{0,100}({service_name}\S+)""",
    """Failure Code:\s{0,100}({result_code}[\w\-]{1,2000})""",
    """Ticket Options:\s{0,100}({ticket_options}[^\s]{1,2000})""",
    """Ticket Encryption Type:\s{0,100}({ticket_encryption_type}[^\s]{1,2000})"""
  ]
}
```