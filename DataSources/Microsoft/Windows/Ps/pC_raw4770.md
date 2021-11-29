#### Parser Content
```Java
{
Name = raw-4770
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-4770"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """A Kerberos service ticket was renewed""", """4770""" ]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """({host}[\w\-.]{1,2000})\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)[\s,]({host}[\w.-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\s({host}[\w\-.]{1,2000})""",
    """__li_source_path="{0,20}({host}[^"]{1,2000})"""",
    """<?Computer>?(Name)?\s{0,100}=?\s{0,100}"{0,20}({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """({event_code}4770)""",
    """Account Name(:|=)\s{0,100}({user}[^@;\s]{1,2000}).+?[\s;]{0,2000}Account Domain""",
    """Account Domain(:|=)\s{0,100}({domain}.+?)[\s;]{0,2000}Service Information""",
    """Service Name(:|=)\s{0,100}({service_name}.+?)[\s;]{0,2000}Service ID(:|=)""",
    """Service Name(:|=)\s{0,100}(::ffff:)?({dest_host}.+?\$)[\s;]{0,2000}Service ID(:|=)""",
    """Ticket Options(:|=)\s{0,100}({ticket_options}.+?)[\s;]{0,2000}Ticket Encryption Type(:|=)"""
    """Ticket Encryption Type(:|=)\s{0,100}({ticket_encryption_type}[^\s;]{1,2000})"""
    """Client Address(:|=)\s{0,100}(::[\w]{1,2000}:)?(::ffff:)?({src_ip}[a-fA-F:\d.]{1,2000})"""
  ]


}
```