#### Parser Content
```Java
{
Name = raw-674
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-674"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Ticket Renewed:", "Ticket Options:" ] 
  Fields = [ 
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{4})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100},\s{0,100}({host}[^,]{1,2000})""",                        
    """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
    """({event_code}674)""",
    """User Name:\s{0,100}({user}[^@]{1,2000}).+?\s{1,100}""",
    """User Domain:\s{0,100}({domain}.+?)\s{1,100}Service Name:""",
    """Service Name:\s{0,100}({service_name}.+?)\s{1,100}Service ID:""",
    """Ticket Options:\s{0,100}({ticket_options}[^\s]{1,2000})""",
    """Ticket Encryption Type:\s{0,100}({ticket_encryption_type}[^\s]{1,2000})""",
    """Client Address:\s{0,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})"""
  ]
}
```