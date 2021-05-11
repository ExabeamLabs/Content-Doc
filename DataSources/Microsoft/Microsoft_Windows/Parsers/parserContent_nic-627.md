#### Parser Content
```Java
{
Name = nic-627
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = RsaSa
    DataType = "windows-password-change"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "MSWinEventLog", " 627 Security", "Change Password Attempt:" ]
    Fields = [
      """({event_name}Change Password Attempt)""",
      """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
      """({event_code}627)""",
      """Information\s{1,100}({host}[\w.\-]+)\s{1,100}""",
      """(?:Success|Failure|Audit)\s{1,100}\w+\s{1,100}({host}[^\s]+)""",
      """Target Account Name:\s{1,100}(?=\w)({target_user}.+?)\s{1,100}Target Domain:\s{1,100}(?=\w)({target_domain}.+?)\s{1,100}Target Account ID:\s\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]+,({logon_id}[^\)]+)"""
    ]
    DupFields=[ "host->dest_host" ]
  }
```