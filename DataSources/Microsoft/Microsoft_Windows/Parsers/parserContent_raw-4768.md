#### Parser Content
```Java
{
Name = raw-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["A Kerberos authentication ticket (TGT) was requested", "Account Name:"]
    Fields = [
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\-.]+)\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({event_code}4768)""",
      """Account Name:\s{0,100}({user}[^@;\s]+?)(?:@.+?)?[\s;]*Supplied Realm Name""",
      """Client Address:\s{0,100}(::[\w]+:)?(::1|({dest_ip}[a-fA-F:\d.]+))""",
      """Result Code:\s{0,100}({result_code}[^:]+?)[\s;]*Ticket Encryption Type""",
      """Supplied Realm Name:\s{0,100}(-|({domain}[^\s]+?))[\s;]*User ID""",
      """Supplied Realm Name:\s{0,100}[^"]*?User ID:\s{0,100}(?:NULL SID|({user_sid}[^\s]+?))[\s;]*Service Information""",
      """Ticket Options:\s{0,100}({ticket_options}[^\s]+?)[\s;]*Result Code:""",
      """Ticket Encryption Type:\s{0,100}({ticket_encryption_type}[^\s]+?)[\s;]*Pre-Authentication Type:""",
      """Service Name:\s{0,100}({service_name}[^\s]+?)[\s;]*Service ID:"""
    ]
    DupFields = ["host->dest_host"]
  }
```