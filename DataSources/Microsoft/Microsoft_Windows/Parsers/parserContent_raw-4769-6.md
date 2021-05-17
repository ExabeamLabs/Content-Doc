#### Parser Content
```Java
{
Name = raw-4769-6
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""ComputerName=""", """EventID=4769""", """Microsoft-Windows-Security-Auditing"""]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """DetectTime(?::|=)({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
      """"dhn":"({host}[^-"]{1,2000})""",
      """({event_code}4769)""",
      """Account Domain(?::|=)({domain}[^\s]{1,2000})""",
      """Account Name(?::|=)(?:[^\/]{1,2000}\/)?({user_email}[^@]{1,2000}@[^\s]{1,2000})""",
      """Failure Code(?::|=)({result_code}[^\s]{1,2000})""",
      """Ticket Encryption Type(?::|=)({ticket_encryption_type}[^\s]{1,2000})""",
      """Client Address(?::|=)\s{0,100}(::[\w]{1,2000}:)?({src_ip}[^\s]{1,2000})""",
      """ComputerName(?::|=)({host}[^\s]{1,2000})\s""",
      """Client Port(?::|=)({src_port}\d{1,100})""",
      """Logon GUID(?::|=)\{?({user_logon_guid}[^\}\s]{1,2000})""",
      """Ticket Options(:|=)\s{0,100}({ticket_options}[^\s]{1,2000})"""
      """EventType(:|=)\s{0,100}({outcome}[^\s]{1,2000})""",
      """Account Name(:|=)\s{0,100}([^\/]{1,2000}\/)?({user}[^@:\s;]{1,2000})(@({domain}[\w._\-]{1,2000}))?[\s;]{0,2000}Account"""
    ]
  }
```