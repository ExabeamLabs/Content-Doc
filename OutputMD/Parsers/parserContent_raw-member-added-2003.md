#### Parser Content
```Java
{
Name = raw-member-added-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Security Enabled", "Group Member Added" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Added)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+),""",
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_source=({host}[A-Fa-f:\d.]+)""",
    """\sexabeam_HostID=({host}[\w\-.]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s+)({host}[\w.\-]+)""",
    """Computer=({host}[\w\-.]+)""",
    """EventID=({event_code}\d+)""",
    """\d\d:\d\d:\d\d\s+\d\d\d\d(\s+|,)({event_code}\d+)(\s|,)+Security""",
    """Security Enabled ({group_type}[^\s]+) Group Member""",
    """Member ID:\s+(?:\%\{)?({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s\}]+))\}?""",
    """Target Account Name:\s+({group_name}.+?)\s+Target Domain:\s+({group_domain}[^\s]+)""",
    """Target Account ID:\s+%\{({group_id}[\w\-]+)""",
    """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\([^,\s]+[,\s]({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s+({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s+Member ID""",
    """Security,({record_id}\d+)""",
    """\sexabeam_ObjectID=({group_name}.+?)\sexabeam_DomainID""",
    """\sexabeam_DomainID=({domain}[^\s]+)""",
    """\sexabeam_Source_Logon_ID=({logon_id}[^\s]+)""",
    """\sexabeam_Security_ID=({account_id}[^\s]+)""",
    """\sexabeam_UserIDDst=({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\sexabeam_Source_Logon_ID="""
  ]
  DupFields = [ "host->dest_host" ]
}
```