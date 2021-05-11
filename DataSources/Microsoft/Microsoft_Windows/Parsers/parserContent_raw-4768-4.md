#### Parser Content
```Java
{
Name = raw-4768-4
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["A Kerberos authentication ticket (TGT) was requested", "Account Name", "computer_name"]
    Fields = [
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """"(?:winlog\.)?computer_name\\*":\\*"({host}[^\\"]+)""",
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_code}4768)""",
      """Account Name(:|=)\s{0,100}({user}[^@;\s]+?)(?:@.+?)?[\s;]*Supplied Realm Name""",
      """Client Address(:|=)\s{0,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """Result Code(:|=)\s{0,100}({result_code}.+?)[\s;]*Ticket Encryption Type(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}(-|({domain}[^\s]+?))[\s;]*User ID(:|=)""",
      """Supplied Realm Name(:|=)\s{0,100}.*?User ID(:|=)\s{0,100}(?:NULL SID|({user_sid}[^\s]+?))[\s;]*Service Information"""
    ]
  }
```