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
    """({host}[\w\-.]+)\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)[\s,]({host}[\w.-]+)""",
    """__li_source_path="{0,20}({host}[^"]+)"""",
    """<?Computer>?(Name)?\s{0,100}=?\s{0,100}"{0,20}({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """({event_code}4770)""",
    """Account Name(:|=)\s{0,100}({user}[^@;\s]+).+?[\s;]*Account Domain""",
    """Account Domain(:|=)\s{0,100}({domain}.+?)[\s;]*Service Information""",
    """Service Name(:|=)\s{0,100}({service_name}.+?)[\s;]*Service ID(:|=)""",
    """Service Name(:|=)\s{0,100}({dest_host}.+?\$)[\s;]*Service ID(:|=)""",
    """Ticket Options(:|=)\s{0,100}({ticket_options}.+?)[\s;]*Ticket Encryption Type(:|=)"""
    """Ticket Encryption Type(:|=)\s{0,100}({ticket_encryption_type}[^\s;]+)"""
    """Client Address(:|=)\s{0,100}(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)"""
  ]
}
```