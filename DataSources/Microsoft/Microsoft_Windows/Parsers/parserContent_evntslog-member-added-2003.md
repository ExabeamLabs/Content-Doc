#### Parser Content
```Java
{
Name = evntslog-member-added-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-added"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "EvntSLog:", "Group Member Added:", "Security Enabled" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Added)""",
    """({host}[^\/\s]+)\/Security \(({event_code}\d{1,100})\)""",
    """EvntSLog:\s{1,100}\[.+\]\s{1,100}\w+\s({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}):""",
    """Security Enabled ({group_type}[^\s]+) Group Member.+?Member ID:\s{1,100}%\{({account_id}[\w\-]+).+?Target Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target Domain:\s{1,100}({group_domain}[^\s]+).+?Target Account ID:\s{1,100}%\{({group_id}[\w\-]+).+Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:[^(]+\([^,]+,({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s{1,100}Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```