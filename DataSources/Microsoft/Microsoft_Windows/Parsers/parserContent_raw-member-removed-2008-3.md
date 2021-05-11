#### Parser Content
```Java
{
Name = raw-member-removed-2008-3
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-removed"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "Security ID:", "Logon ID:", "A member was removed from a security-enabled", "Computer" ]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """Computer(Name|_name)?["\s]*(:|=|\\=)\s{0,100}"?({host}.+?)("|\s)""",
    """"?Event(ID)?Code["\s]*(:|=|\\=)\s{0,100}"?({event_code}\d{1,100})""",
    """({event_code}\d{1,100})\s{1,100}Microsoft-Windows-Security-Auditing""",
    """A member was removed from a security-enabled\s{0,100}({group_type}[^\s]+)\s{1,100}group""",
    """Account Name\s{0,100}:\s{0,100}({user}[^\s]+)\s{0,100}Account Domain\s{0,100}:\s{0,100}({domain}[^\s]+)\s{1,100}""",
    """Logon ID:\s{0,100}({logon_id}[^\s]+)\s{1,100}""",
    """Member:\s{0,100}Security ID\s{0,100}:\s{0,100}({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\\\s]+)|(?:.*?))\s{0,100}Account Name:""",
    """Account Name\s{0,100}:\s{0,100}(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))|(?:.+?))\s{0,100}Group:""",
    """Group\s{0,100}:\s{0,100}Security ID\s{0,100}:\s{0,100}({group_id}[^\s]+)\s{0,100}""",
    """Group:.+?(Group|Account) Name\s{0,100}:\s{0,100}({group_name}.+?)?\s{0,100}(Group|Account) Domain\s{0,100}:\s{0,100}({group_domain}[^\s]+)\s{0,100}""",
  ]
  DupFields = [ "host->dest_host" ]
}
```