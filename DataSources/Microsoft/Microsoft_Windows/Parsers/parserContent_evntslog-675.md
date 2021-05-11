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
    Fields = [ """({time}\w+ \d{1,2} [\d:]+ \d{1,100}):""",
      """({event_name}Pre-authentication failed)""",
      """({host}[^\/\s]+)\/Security \(({event_code}675)\)""",
      """User Name:\s{1,100}({user}.+?)\s{1,100}User ID:\s\%\{({user_sid}[^}]+)\}""",
      """Service Name:\s{1,100}\w+\/(?=\w)({domain}.+?)\s{1,100}Pre-Authentication""",
      """Failure Code:\s{1,100}({result_code}[\w]+)""",
      """Client Address:\s{1,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
    ]
    DupFields = ["host->dest_host"]
  }
```