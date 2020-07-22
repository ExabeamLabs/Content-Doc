#### Parser Content
```Java
{
Name = raw-628
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct 
    DataType = "windows-password-reset"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "User Account password set:"]
    Fields = [
      """({event_name}User Account password set)""",
      """({time}\w+ \d{1,2} [\d:]+ \d+)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(information)(,|\s+)({host}[\w.\-]+)""",
      """(?i)((audit|success|failure)( |_)(success|audit|failure))\s+({host}[\w\-.]+)\s+Account Management""",
      """({host}[^\/\s]+)\/Security""",
      """ComputerName=({host}[\w.\-]+)""",
      """({event_code}628)""",
      """Target Account Name:\s+({target_user}.+?)\s+Target Domain:\s+({target_domain}.+?)\s+Target Account ID:\s\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s+(?=\w)({user}.+?)\s+Caller Domain:\s+(?=\w)({domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^\)]+)""",
      """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\(.+?\s+({logon_id}[^\s)]+)\)"""
    ]
    DupFields=["host->dest_host" ]
  }
```