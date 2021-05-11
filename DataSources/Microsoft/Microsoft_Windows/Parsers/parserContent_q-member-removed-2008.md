#### Parser Content
```Java
{
Name = q-member-removed-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-member-removed"
  TimeFormat = "epoch_sec"
  Conditions = [ "A member was removed from a security-enabled", "EventID=" ]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """EventID=({event_code}\d{1,100})""",
    """TimeGenerated=({time}\d{1,100})""",
    """Computer=({host}[^\s]+)""",
    """A member was removed from a security-enabled ({group_type}[^\s]+) group.+?Account Name:\s{1,100}({user}[^\s]+).+?Account Domain:\s{1,100}({domain}[^\s]+).+?Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}""",
    """Member:\s{1,100}Security ID:\s{1,100}({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s]+))\s{1,100}Account Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))?\s{1,100}Group:\s{1,100}Security ID:\s{1,100}({group_id}[^\s]+).+?\s{1,100}(Group|Account) Name:\s{1,100}({group_name}[^\s]+)?.+?\s{1,100}(Group|Account) Domain:\s{1,100}({group_domain}[^\s]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```