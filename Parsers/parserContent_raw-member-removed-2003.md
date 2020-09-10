#### Parser Content
```Java
{
Name = raw-member-removed-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-removed"
  TimeFormat = "epoch_sec"
  Conditions = [ "Group Member Removed:", "Security Enabled", ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Removed)""",
    """TimeGenerated=({time}\d+)""",
    """exabeam_host=({host}[\w\-.]+)""",
    """(?i)(success|failure|audit)\s+\w+\s+({host}[\w\-.]+)""",
    """Information(,|\s+)({host}[\w.\-]+)""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
    """Event(Code|ID)=({event_code}\d+)""",
    """\d\d:\d\d:\d\d\s+\d\d\d\d\s+({event_code}\d+)\s+Security""",
    """Security Enabled\s+({group_type}[^\s]+)\s+Group Member""",
    """Group Member.+?Member ID:\s+(%\{)?({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s}]+)).+Target""",
    """Target Account Name:\s+({group_name}.+?)\s+Target Domain:\s+({group_domain}[^\s]+).+?Target Account ID:\s+%\{({group_id}[\w\-]+).+Caller""",
    """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\([^,\s]+(\s|,)({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s+(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))\s+Member ID"""
  ]
  DupFields = [ "host->dest_host" ]
}
```