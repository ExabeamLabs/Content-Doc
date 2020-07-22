#### Parser Content
```Java
{
Name = raw-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["A Kerberos authentication ticket (TGT) was requested", "Account Name"]
    Fields = [
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4768\)""",
      """"dhn":"({host}[^-"]+)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s|;)""",
      """({event_code}4768)""",
      """Account Name(:|=)\s*({user}[^@;]+?)(?:@.+?)?[\s;]*Supplied Realm Name""",
      """Client Address(:|=)\s*(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """Result Code(:|=)\s*({result_code}.+?)[\s;]*Ticket Encryption Type(:|=)""",
      """Supplied Realm Name(:|=)\s*({domain}.+?)[\s;]*User ID(:|=)\s*(?:NULL SID|({user_sid}.+?))[\s;]*Service Information"""
    ]
  }
```