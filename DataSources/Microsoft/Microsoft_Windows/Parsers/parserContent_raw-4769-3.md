#### Parser Content
```Java
{
Name = raw-4769-3
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["A Kerberos service ticket was requested", "Account Name", "Computer"]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s|;)""",
      """({event_code}4769)""",
      """Account Name(:|=)\s*({user}[^@:\s;]+)(@({domain}[\w._\-]+))?[\s;]*Account Domain(:|=)""",
      """Service Name(:|=)\s*({dest_host}[^\s;]+\$)[\s;]*Service ID""",
      """Service Name(:|=)\s*({service_name}[^\s;]+)[\s;]*Service ID""",
      """Client Address(:|=)\s*(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
      """Failure Code(:|=)\s*({result_code}.+?)[\s;]*Transited Services(:|=)""",
      """Ticket Options(:|=)\s*({ticket_options}.+?)[\s;]*Ticket Encryption Type(:|=)"""
      """Ticket Encryption Type(:|=)\s*({ticket_encryption_type}.+?)[\s;]*Failure Code(:|=)"""
    ]
  }
```