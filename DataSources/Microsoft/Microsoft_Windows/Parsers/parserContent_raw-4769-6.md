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
      """DetectTime(?::|=)({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
      """"dhn":"({host}[^-"]+)""",
      """({event_code}4769)""",
      """Account Domain(?::|=)({domain}[^\s]+)""",
      """Account Name(?::|=)(?:[^\/]+\/)?({user_email}[^@]+@[^\s]+)""",
      """Failure Code(?::|=)({result_code}[^\s]+)""",
      """Ticket Encryption Type(?::|=)({ticket_encryption_type}[^\s]+)""",
      """Client Address(?::|=)\s*(::[\w]+:)?({src_ip}[^\s]+)""",
      """ComputerName(?::|=)({host}[^\s]+)\s""",
      """Client Port(?::|=)({src_port}\d+)""",
      """Logon GUID(?::|=)\{?({user_logon_guid}[^\}\s]+)""",
      """Ticket Options(:|=)\s*({ticket_options}[^\s]+)"""
      """EventType(:|=)\s*({outcome}[^\s]+)""",
      """Account Name(:|=)\s*([^\/]+\/)?({user}[^@:\s;]+)(@({domain}[\w._\-]+))?[\s;]*Account"""
    ]
  }
```