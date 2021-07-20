#### Parser Content
```Java
{
Name = raw-4769-2
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["A Kerberos service ticket was requested", "Account Name", "Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
      """(::ffff:)?({host}[^\s\/]{1,2000})\/Microsoft-Windows-Security-Auditing \(4769\)""",
      """({event_code}4769)""",
      """Account Name(:|=)\s{0,100}({user}[^@:\s;]{1,2000})(@({domain}[\w._\-]{1,2000}))?[\s;]{0,2000}Account Domain(:|=)""",
      """Service Name(:|=)\s{0,100}(::ffff:)?({dest_host}[^\s;]{1,2000}\$)[\s;]{0,2000}Service ID""",
      """Service Name(:|=)\s{0,100}({service_name}[^\s;]{1,2000})[\s;]{0,2000}Service ID""",
      """Client Address(:|=)\s{0,100}(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})""",
      """Failure Code(:|=)\s{0,100}({result_code}.+?)[\s;]{0,2000}Transited Services(:|=)""",
      """Ticket Options(:|=)\s{0,100}({ticket_options}.+?)[\s;]{0,2000}Ticket Encryption Type(:|=)"""
      """Ticket Encryption Type(:|=)\s{0,100}({ticket_encryption_type}.+?)[\s;]{0,2000}Failure Code(:|=)"""
    ]
  }
```