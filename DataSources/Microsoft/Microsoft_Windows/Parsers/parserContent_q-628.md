#### Parser Content
```Java
{
Name = q-628
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = QRadar
    DataType = "windows-password-reset"
    TimeFormat = "epoch_sec"
    Conditions = [ "EventIDCode=628" ]
    Fields = [
      """({event_name}User Account password set)""",
      """TimeGenerated=({time}\d+)""",
      """Computer=({host}[^\s]+)""",
      """EventID=({event_code}\d+)""",
      """Target Account Name:\s+({target_user}.+?)\s+Target Domain:\s+({target_domain}.+?)\s+Target Account ID:\s*({target_user_sid}.+?)\s+Caller User""",
      """Caller User Name:\s+(?=\w)({user}.+?)\s+Caller Domain:\s+(?=\w)({domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^\)]+)"""
    ]
    DupFields=["host->dest_host" ]
  }
```