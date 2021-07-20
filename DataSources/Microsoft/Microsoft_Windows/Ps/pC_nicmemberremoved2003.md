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
    """({event_name}Security Enabled [\w\s]{1,2000} Group Member Removed)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """\d\d:\d\d:\d\d\s{1,100}\d\d\d\d\s{1,100}({event_code}\d{1,100})\s{1,100}Security""",
    """(?:Success|Failure|Audit)\s{1,100}\w+\s{1,100}({host}[^\s]{1,2000})""",
    """Information\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}""",
    """Security Enabled\s{1,100}({group_type}.+?)\s{1,100}Group Member""",
    """Member ID:\s{1,100}%\{({account_id}[\w\-]{1,2000})""",
    """Target Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target Domain:\s{1,100}({group_domain}.+?)\s{1,100}Target Account ID:\s{1,100}%\{({group_id}[\w\-]{1,2000})""",
    """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\(\w+(\s|,)({logon_id}[^)]{1,2000})""",
    """Group Member.+?Member Name:\s{1,100}(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]{1,2000})))\s{1,100}Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```