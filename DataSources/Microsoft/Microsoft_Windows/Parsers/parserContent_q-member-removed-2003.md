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
    """EventID=({event_code}\d{1,100})""",
    """TimeGenerated=({time}\d{1,100})""",
    """Computer=({host}[^\s]+)""",
    """Security Enabled ({group_type}[^\s]+) Group Member""",
    """Group Member.+?Member ID:\s{1,100}(%\{)?({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s}]+)).+Target Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target Domain:\s{1,100}({group_domain}[^\s]+).+?Target Account ID:\s{1,100}%\{({group_id}[\w\-]+).+Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]+,({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s{1,100}Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```