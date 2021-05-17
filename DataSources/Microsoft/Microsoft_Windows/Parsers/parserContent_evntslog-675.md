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
    Fields = [ """({time}\w+ \d{1,2} [\d:]{1,2000} \d{1,100}):""",
      """({event_name}Pre-authentication failed)""",
      """({host}[^\/\s]{1,2000})\/Security \(({event_code}675)\)""",
      """User Name:\s{1,100}({user}.+?)\s{1,100}User ID:\s\%\{({user_sid}[^}]{1,2000})\}""",
      """Service Name:\s{1,100}\w+\/(?=\w)({domain}.+?)\s{1,100}Pre-Authentication""",
      """Failure Code:\s{1,100}({result_code}[\w]{1,2000})""",
      """Client Address:\s{1,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})"""
    ]
    DupFields = ["host->dest_host"]
  }
```