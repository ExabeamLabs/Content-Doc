#### Parser Content
```Java
{
Name = raw-windows-account-624
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "User Account Created" ]
  Fields = [ 
    """({event_name}User Account Created)""",
             """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
             """({event_code}624)""",
             """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
             """({host}[^\/\s]+)\/Security \(624\)""",
             """Computer=({host}[^\s]+)""",
             """New Account Name:\s+({account_name}.+?)\s+New Domain:\s+({account_domain}[^\s]+)\s+New Account ID:\s+(%\{)?({account_id}[^\s\}]+)""",
             """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}[^\s]+)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^)]+)""" 
   ]
   DupFields = ["host->dest_host"]
}
```