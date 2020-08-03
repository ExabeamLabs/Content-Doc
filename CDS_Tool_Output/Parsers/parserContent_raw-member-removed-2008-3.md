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
    """Computer(Name|_name)?["\s]*(:|=|\\=)\s*"?({host}.+?)("|\s)""",
    """"?Event(ID)?Code["\s]*(:|=|\\=)\s*"?({event_code}\d+)""",
    """({event_code}\d+)\s+Microsoft-Windows-Security-Auditing""",
    """A member was removed from a security-enabled\s*({group_type}[^\s]+)\s+group""",
    """Account Name\s*:\s*({user}[^\s]+)\s*Account Domain\s*:\s*({domain}[^\s]+)\s+""",
    """Logon ID:\s*({logon_id}[^\s]+)\s+""",
    """Member:\s*Security ID\s*:\s*({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\\\s]+)|(?:.*?))\s*Account Name:""",
    """Account Name\s*:\s*(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))|(?:.+?))\s*Group:""",
    """Group\s*:\s*Security ID\s*:\s*({group_id}[^\s]+)\s*""",
    """Group:.+?(Group|Account) Name\s*:\s*({group_name}.+?)?\s*(Group|Account) Domain\s*:\s*({group_domain}[^\s]+)\s*""",
  ]
  DupFields = [ "host->dest_host" ]
}
```