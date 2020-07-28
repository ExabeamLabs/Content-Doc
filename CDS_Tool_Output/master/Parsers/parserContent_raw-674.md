#### Parser Content
```Java
{
Name = raw-674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-674"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Ticket Renewed:", "Ticket Options:" ] 
  Fields = [ 
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{4})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s*,\s*({host}[^,]+)""",                        
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
    """({event_code}674)""",
    """User Name:\s*({user}[^@]+).+?\s+""",
    """User Domain:\s*({domain}.+?)\s+Service Name:""",
    """Service Name:\s*({service_name}.+?)\s+Service ID:""",
    """Ticket Options:\s*({ticket_options}[^\s]+)""",
    """Ticket Encryption Type:\s*({ticket_encryption_type}[^\s]+)""",
    """Client Address:\s*(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
  ]
}
```