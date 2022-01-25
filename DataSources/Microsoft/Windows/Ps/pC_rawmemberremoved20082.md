#### Parser Content
```Java
{
Name = raw-member-removed-2008-2
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-member-removed"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "Security ID:", "Logon ID:", "A member was removed from a security-enabled", "_raw" ]
  Fields = [
    """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """({event_name}A member was removed from a security-enabled [\w\s]{1,2000} group)""",
    """"_raw":"({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """exabeam_host=(gcs-topic|({host}[\w\-.]{1,2000}))""",
    """"agent_hostname":"({host}[^"]{1,200})"""",
    """"computer":"({host}[^"]{1,200})"""",
    """(?i)(success|audit)\s{1,100}\w+\s{1,100}({host}[\w\-.]{1,2000})""",
    """"?Event(ID)?Code["\s]{0,2000}(:|=|\\=)\s{0,100}"?({event_code}\d{1,100})""",
    """({event_code}\d{1,100})\s{1,100}Microsoft-Windows-Security-Auditing""",
    """A member was removed from a security-enabled\s{0,100}({group_type}[^\s]{1,2000})\s{1,100}group""",
    """Account Name\s{0,100}:\s{0,100}({user}[^\s]{1,2000})\s{0,100}Account Domain\s{0,100}:\s{0,100}({domain}[^\s]{1,2000})\s{1,100}""",
    """Logon ID:\s{0,100}({logon_id}[^\s]{1,2000})\s{1,100}""",
    """Member:\s{0,100}Security ID\s{0,100}:\s{0,100}({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}[^\\\s]{1,2000})|(?:.*?))\s{0,100}Account Name:""",
    """Account Name\s{0,100}:\s{0,100}(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))|(?:.+?))\s{0,100}Group:""",
    """Group\s{0,100}:\s{0,100}Security ID\s{0,100}:\s{0,100}({group_id}[^\s]{1,2000})\s{0,100}""",
    """Group:.+?(Group|Account) Name\s{0,100}:\s{0,100}({group_name}.+?)?\s{0,100}(Group|Account) Domain\s{0,100}:\s{0,100}({group_domain}[^\s]{1,2000})\s{0,100}""",
  ]
  DupFields = [ "host->dest_host" ]


}
```