#### Parser Content
```Java
{
Name = evntslog-675
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-675"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["(675)", "Pre-authentication failed"]
    Fields = [ """({time}\w+ \d{1,2} [\d:]+ \d+):""",
      """({event_name}Pre-authentication failed)""",
      """({host}[^\/\s]+)\/Security \(({event_code}675)\)""",
      """User Name:\s+({user}.+?)\s+User ID:\s\%\{({user_sid}[^}]+)\}""",
      """Service Name:\s+\w+\/(?=\w)({domain}.+?)\s+Pre-Authentication""",
      """Failure Code:\s+({result_code}[\w]+)""",
      """Client Address:\s+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
    ]
  }
```