#### Parser Content
```Java
{
Name = raw-4769-5
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["A Kerberos service ticket was requested", "Account Name", "computer_name"]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """({event_code}4769)""",
      """"computer_name\\*":\\*"({host}[^\\"]+)""",
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
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