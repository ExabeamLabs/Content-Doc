#### Parser Content
```Java
{
Name = raw-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4770"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "A Kerberos service ticket was renewed", "4770" ]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)[\s,]({host}[\w.-]+)""",
    """__li_source_path="*({host}[^"]+)"""",
    """<?Computer>?(Name)?\s*=?\s*"*({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """({event_code}4770)""",
    """Account Name(:|=)\s*({user}[^@;\s]+).+?[\s;]*Account Domain""",
    """Account Domain(:|=)\s*({domain}.+?)[\s;]*Service Information""",
    """Service Name(:|=)\s*({service_name}.+?)[\s;]*Service ID(:|=)""",
    """Service Name(:|=)\s*({dest_host}.+?\$)[\s;]*Service ID(:|=)""",
    """Ticket Options(:|=)\s*({ticket_options}.+?)[\s;]*Ticket Encryption Type(:|=)"""
    """Ticket Encryption Type(:|=)\s*({ticket_encryption_type}[^\s;]+)"""
    """Client Address(:|=)\s*(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)"""
  ]
}
```