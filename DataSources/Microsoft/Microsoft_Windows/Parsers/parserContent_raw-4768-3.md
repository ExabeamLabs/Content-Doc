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
      """({time}\d\d\/\d\d\/\d\d\d\d\s+\d\d:\d\d:\d\d\s+(?i)(AM|PM))""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({event_code}4768)""",
      """Account Name(:|=)\s*({user}[^@;\s]+?)(?:@.+?)?[\s;]*Supplied Realm Name""",
      """Client Address(:|=)\s*(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """Result Code(:|=)\s*({result_code}.+?)[\s;]*Ticket Encryption Type(:|=)""",
      """Supplied Realm Name(:|=)\s*(-|({domain}[^\s]+?))[\s;]*User ID(:|=)""",
      """Supplied Realm Name(:|=)\s*.*?User ID(:|=)\s*(?:NULL SID|({user_sid}[^\s]+?))[\s;]*Service Information""",
      """Pre-Authentication\sType(:|=)\s*({pre_auth}[^\s]+)"""
    ]
  }
```