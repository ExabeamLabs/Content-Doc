#### Parser Content
```Java
{
Name = raw-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["A Kerberos service ticket was requested", "Account Name"]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """({host}[\w.\-]+)\s*:\s+A Kerberos service ticket was requested""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4769\)""",
      """"dhn":"({host}[^-"]+)""",
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