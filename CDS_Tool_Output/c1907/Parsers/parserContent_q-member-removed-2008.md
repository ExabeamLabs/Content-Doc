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
    """EventID=({event_code}\d+)""",
    """TimeGenerated=({time}\d+)""",
    """Computer=({host}[^\s]+)""",
    """A member was removed from a security-enabled ({group_type}[^\s]+) group.+?Account Name:\s+({user}[^\s]+).+?Account Domain:\s+({domain}[^\s]+).+?Logon ID:\s+({logon_id}[^\s]+)\s+""",
    """Member:\s+Security ID:\s+({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s]+))\s+Account Name:\s+({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))?\s+Group:\s+Security ID:\s+({group_id}[^\s]+).+?\s+(Group|Account) Name:\s+({group_name}[^\s]+)?.+?\s+(Group|Account) Domain:\s+({group_domain}[^\s]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```