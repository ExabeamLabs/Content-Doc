#### Parser Content
```Java
{
Name = xml-4769-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
    Conditions = ["<EventID>4769</EventID>", "A Kerberos service ticket was requested", "Account Name", "Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)'\/>""",
      """Computer>({host}[^<]+)<\/Computer""",
      """({event_code}4769)""",
      """Account Name(:|=)\s{0,100}({user}[^@:\s;]+)(@({domain}[\w._\-]+))?[\s;]*Account Domain(:|=)""",
      """Service Name(:|=)\s{0,100}({dest_host}[^\s;]+\$)[\s;]*Service ID""",
      """Service Name(:|=)\s{0,100}({service_name}[^\s;]+)[\s;]*Service ID""",
      """Client Address(:|=)\s{0,100}(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
      """Failure Code(:|=)\s{0,100}({result_code}.+?)[\s;]*Transited Services(:|=)""",
      """Ticket Options(:|=)\s{0,100}({ticket_options}.+?)[\s;]*Ticket Encryption Type(:|=)""",
      """Ticket Encryption Type(:|=)\s{0,100}({ticket_encryption_type}.+?)[\s;]*Failure Code(:|=)""",
    ]
  }
```