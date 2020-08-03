#### Parser Content
```Java
{
Name = nic-member-removed-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-member-removed"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [   "MSWinEventLog", "Group Member Removed:", "Security Enabled" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Removed)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """\d\d:\d\d:\d\d\s+\d\d\d\d\s+({event_code}\d+)\s+Security""",
    """(?:Success|Failure|Audit)\s+\w+\s+({host}[^\s]+)""",
    """Information\s+({host}[\w.\-]+)\s+""",
    """Security Enabled\s+({group_type}.+?)\s+Group Member""",
    """Member ID:\s+%\{({account_id}[\w\-]+)""",
    """Target Account Name:\s+({group_name}.+?)\s+Target Domain:\s+({group_domain}.+?)\s+Target Account ID:\s+%\{({group_id}[\w\-]+)""",
    """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\(\w+(\s|,)({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s+(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))\s+Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```