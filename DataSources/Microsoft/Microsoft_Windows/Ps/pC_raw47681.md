#### Parser Content
```Java
{
Name = raw-4768-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["A Kerberos authentication ticket (TGT) was requested", "Account Name", "dhn"]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""", 
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """"dhn":"({host}[^-"]{1,2000})""",
      """({event_code}4768)""",
      """Account Name(:|=)\s{0,100}({user}[^@;\s]{1,2000}?)(?:@.+?)?[\s;]{0,2000}Supplied Realm Name""",
      """Client Address(:|=)\s{0,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """Result Code(:|=)\s{0,100}({result_code}.+?)[\s;]{0,2000}Ticket Encryption Type(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}User ID(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}.*?User ID(:|=)\s{0,100}(?:NULL SID|({user_sid}[^\s]{1,2000}?))[\s;]{0,2000}Service Information"""
    ]
  }
```