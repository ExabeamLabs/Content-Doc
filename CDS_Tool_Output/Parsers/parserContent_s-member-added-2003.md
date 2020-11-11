#### Parser Content
```Java
{
Name = s-member-added-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-added"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """LogName=""", """SourceName=""", "Group Member Added:", "Security Enabled", "EventCode=" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Added)""",
    """exabeam_raw=({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """ComputerName=({host}[\w.\-]+)""",
    """EventCode=({event_code}\w+)""",
    """Security Enabled ({group_type}[^\s]+) Group Member""",
    """Group Member.+?Member ID:\s+({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s+Target Account""",
    """Target Account Name:\s+({group_name}.+?)\s+Target""",
    """Target Domain:\s+({group_domain}[^\s]+)""",
    """Target Account ID:\s+({group_id}.+?)\s+Caller""",
    """Caller User Name:\s+({user}.+?)\s+Caller""",
    """Caller Domain:\s+({domain}.+?)\s+Caller""",
    """Caller Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s+({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s+Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```