#### Parser Content
```Java
{
Name = raw-4768-2
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["A Kerberos authentication ticket (TGT) was requested", "Account Name", "Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""", 
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4768\)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]+))""",
      """({event_code}4768)""",
      """Account Name(:|=)\s{0,100}({user}[^@;\s]+?)(?:@.+?)?[\s;]*Supplied Realm Name""",
      """Client Address(:|=)\s{0,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """Result Code(:|=)\s{0,100}({result_code}.+?)[\s;]*Ticket Encryption Type(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}(-|({domain}[^\s]+?))[\s;]*User ID(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}.*?User ID(:|=)\s{0,100}(?:NULL SID|({user_sid}[^\s]+?))[\s;]*Service Information"""
    ]
  }
```