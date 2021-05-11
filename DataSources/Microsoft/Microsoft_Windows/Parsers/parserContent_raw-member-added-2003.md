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
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}),""",
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_source=({host}[A-Fa-f:\d.]+)""",
    """\sexabeam_HostID=({host}[\w\-.]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s{1,100})({host}[\w.\-]+)""",
    """Computer=({host}[\w\-.]+)""",
    """EventID=({event_code}\d{1,100})""",
    """\d\d:\d\d:\d\d\s{1,100}\d\d\d\d(\s{1,100}|,)({event_code}\d{1,100})(\s|,)+Security""",
    """Security Enabled ({group_type}[^\s]+) Group Member""",
    """Member ID:\s{1,100}(?:\%\{)?({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s\}]+))\}?""",
    """Target Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target Domain:\s{1,100}({group_domain}[^\s]+)""",
    """Target Account ID:\s{1,100}%\{({group_id}[\w\-]+)""",
    """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,\s]+[,\s]({logon_id}[^)]+)""",
    """Group Member.+?Member Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\s{1,100}Member ID""",
    """Security,({record_id}\d{1,100})""",
    """\sexabeam_ObjectID=({group_name}.+?)\sexabeam_DomainID""",
    """\sexabeam_DomainID=({domain}[^\s]+)""",
    """\sexabeam_Source_Logon_ID=({logon_id}[^\s]+)""",
    """\sexabeam_Security_ID=({account_id}[^\s]+)""",
    """\sexabeam_UserIDDst=({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))\sexabeam_Source_Logon_ID="""
  ]
  DupFields = [ "host->dest_host" ]
}
```