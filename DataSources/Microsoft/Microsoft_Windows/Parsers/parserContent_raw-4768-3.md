#### Parser Content
```Java
{
Name = raw-4768-3
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = ["A Kerberos authentication ticket (TGT) was requested", "Account Name", "Computer"]
    Fields = [
      """ComputerName=({host}[\w-.]{1,2000})""",
      """({time}\d\d\/\d\d\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}(?i)(AM|PM))""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({event_code}4768)""",
      """Account Name(:|=)\s{0,100}({user}[^@;\s]{1,2000}?)(?:@.+?)?[\s;]{0,2000}Supplied Realm Name""",
      """Client Address(:|=)\s{0,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """Result Code(:|=)\s{0,100}({result_code}.+?)[\s;]{0,2000}Ticket Encryption Type(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}User ID(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}.*?User ID(:|=)\s{0,100}(?:NULL SID|({user_sid}[^\s]{1,2000}?))[\s;]{0,2000}Service Information""",
      """Pre-Authentication\sType(:|=)\s{0,100}({pre_auth}[^\s]{1,2000})"""
    ]
  }
```