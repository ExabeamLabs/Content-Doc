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
      """ComputerName=({host}[\w-.]+)""",
      """({time}\d\d\/\d\d\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}(?i)(AM|PM))""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({event_code}4768)""",
      """Account Name(:|=)\s{0,100}({user}[^@;\s]+?)(?:@.+?)?[\s;]*Supplied Realm Name""",
      """Client Address(:|=)\s{0,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """Result Code(:|=)\s{0,100}({result_code}.+?)[\s;]*Ticket Encryption Type(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}(-|({domain}[^\s]+?))[\s;]*User ID(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}.*?User ID(:|=)\s{0,100}(?:NULL SID|({user_sid}[^\s]+?))[\s;]*Service Information""",
      """Pre-Authentication\sType(:|=)\s{0,100}({pre_auth}[^\s]+)"""
    ]
  }
```