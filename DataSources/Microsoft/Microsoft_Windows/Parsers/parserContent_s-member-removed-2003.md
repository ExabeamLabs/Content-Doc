#### Parser Content
```Java
{
Name = s-member-removed-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-removed"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ "Group Member Removed:", "Security Enabled", "EventCode=" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Removed)""",
    """exabeam_raw=({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """ComputerName=({host}[\w.\-]+)""",
    """EventCode=({event_code}\w+)""",
    """Security Enabled ({group_type}[^\s]+) Group Member""",
    """Group Member.+?Member ID:\s{1,100}({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s{1,100}Target""",
    """Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target""",
    """Target Domain:\s{1,100}({group_domain}[^\s]+)""",
    """Target Account ID:\s{1,100}({group_id}.+?)\s{1,100}Caller""",
    """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller""",
    """Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller""",
    """Caller Logon ID:\s{1,100}\([^,]+,({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s{1,100}Member ID""",
  ]
  DupFields = [ "host->dest_host" ]
}
```