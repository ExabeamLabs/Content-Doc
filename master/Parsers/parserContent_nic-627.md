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
      """Information\s+({host}[\w.\-]+)\s+""",
      """(?:Success|Failure|Audit)\s+\w+\s+({host}[^\s]+)""",
      """Target Account Name:\s+(?=\w)({target_user}.+?)\s+Target Domain:\s+(?=\w)({target_domain}.+?)\s+Target Account ID:\s\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^\)]+)"""
    ]
    DupFields=[ "host->dest_host" ]
  }
```