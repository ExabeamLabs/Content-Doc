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
             """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
             """({host}[^\/\s]+)\/Security \(624\)""",
             """Computer=({host}[^\s]+)""",
             """New Account Name:\s{1,100}({account_name}.+?)\s{1,100}New Domain:\s{1,100}({account_domain}[^\s]+)\s{1,100}New Account ID:\s{1,100}(%\{)?({account_id}[^\s\}]+)""",
             """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}[^\s]+)\s{1,100}Caller Logon ID:\s{1,100}\([^,]+,({logon_id}[^)]+)""" 
   ]
   DupFields = ["host->dest_host"]
}
```