#### Parser Content
```Java
{
Name = q-member-removed-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-member-removed"
  TimeFormat = "epoch_sec"
  Conditions = [ "Security Enabled", " Group Member Removed" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Removed)""",
    """EventID=({event_code}\d+)""",
    """TimeGenerated=({time}\d+)""",
    """Computer=({host}[^\s]+)""",
    """Security Enabled ({group_type}[^\s]+) Group Member""",
    """Group Member.+?Member ID:\s+(%\{)?({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s}]+)).+Target Account Name:\s+({group_name}.+?)\s+Target Domain:\s+({group_domain}[^\s]+).+?Target Account ID:\s+%\{({group_id}[\w\-]+).+Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s+({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s+Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```