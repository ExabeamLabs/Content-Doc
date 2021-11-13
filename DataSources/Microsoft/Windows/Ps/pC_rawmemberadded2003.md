#### Parser Content
```Java
{
Name = raw-member-added-2003
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Security Enabled", "Group Member Added" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]{1,2000} Group Member Added)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}),""",
    """exabeam_host=(gcs-topic|({host}[\w\-.]{1,2000}))""",
    """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
    """\sexabeam_HostID=({host}[\w\-.]{1,2000})""",
    """"agent_hostname":"({host}[^"]{1,200})"""",
    """"computer":"({host}[^"]{1,200})"""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s{1,100})({host}[\w.\-]{1,2000})""",
    """Computer=({host}[\w\-.]{1,2000})""",
    """EventID=({event_code}\d{1,100})""",
    """\d\d:\d\d:\d\d\s{1,100}\d\d\d\d(\s{1,100}|,)({event_code}\d{1,100})(\s|,)+Security""",
    """Security Enabled ({group_type}[^\s]{1,2000}) Group Member""",
    """Member ID:\s{1,100}(?:\%\{)?({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}[^\s]{1,2000})|(?:[^\s\}]{1,2000}))\}?""",
    """Target Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target Domain:\s{1,100}({group_domain}[^\s]{1,2000})""",
    """Target Account ID:\s{1,100}%\{({group_id}[\w\-]{1,2000})""",
    """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,\s]{1,2000}[,\s]({logon_id}[^)]{1,2000})""",
    """Group Member.+?Member Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))\s{1,100}Member ID""",
    """Security,({record_id}\d{1,100})""",
    """\sexabeam_ObjectID=({group_name}.+?)\sexabeam_DomainID""",
    """\sexabeam_DomainID=({domain}[^\s]{1,2000})""",
    """\sexabeam_Source_Logon_ID=({logon_id}[^\s]{1,2000})""",
    """\sexabeam_Security_ID=({account_id}[^\s]{1,2000})""",
    """\sexabeam_UserIDDst=({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))\sexabeam_Source_Logon_ID="""
  ]
  DupFields = [ "host->dest_host" ]


}
```