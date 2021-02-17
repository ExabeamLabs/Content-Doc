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
    """({host}[^\/\s]+)\/Security \(({event_code}\d+)\)""",
    """EvntSLog:\s+\[.+\]\s+\w+\s({time}\w+ \d+ \d+:\d+:\d+ \d+):""",
    """Security Enabled ({group_type}[^\s]+) Group Member.+?Member ID:\s+%\{({account_id}[\w\-]+).+?Target Account Name:\s+({group_name}.+?)\s+Target Domain:\s+({group_domain}[^\s]+).+?Target Account ID:\s+%\{({group_id}[\w\-]+).+Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:[^(]+\([^,]+,({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s+({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s+Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```