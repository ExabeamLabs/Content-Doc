#### Parser Content
```Java
{
Name = s-627
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-password-change"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = ["EventCode=627", "Change Password Attempt:"]
    Fields = [ 
      """({event_name}Change Password Attempt)""",
      """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """ComputerName=({host}[\w.\-]+)""",
      """\sType=({outcome}.+?)\s+\w+=""",
      """EventCode=({event_code}\d+)""",
      """Target Account Name:\s+(?=\w)({target_user}.+?)\s+Target Domain:\s+(?=\w)({target_domain}.+?)\s+Target Account ID:\s\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^\)]+)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```