#### Parser Content
```Java
{
Name = raw-windows-account-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "A user account was created" ]
  Fields = [ 
    """({event_name}A user account was created)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
             """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
             """({event_code}4720)""",
             """exabeam_host=({host}[A-Fa-f:\d.]+)""",
             """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s+)({host}[\w.\-]+),?""",
             """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing \(4720\)""",
             """"dhn":"({host}[^-"]+)""",
             """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
             """"system_name":"({host}[^"]+)"""",
             """Security(,|\srn=)({record_id}\d+)""",
             """Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}[^\s]+).+?Logon ID:\s+({logon_id}[^\s]+).+?Account Name:\s+({account_name}.+?)\s+Account Domain:\s+({account_domain}[^\s]+)\s+Attributes""",
             """Subject:\s+Security ID:\s+({user_sid}[^\s]+).+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}[^\s]+).+?Logon ID:\s+({logon_id}[^\s]+)""",
             """New Account:.+?Security ID:\s+({account_id}[^\s]+)\s+Account Name:\s+({account_name}[\w.'\-]+)\s+Account Domain:\s+({account_domain}[^\s]+)""",]
}
```