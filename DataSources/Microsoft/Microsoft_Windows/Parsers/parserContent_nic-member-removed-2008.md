#### Parser Content
```Java
{
Name = nic-member-removed-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-member-removed"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [  "MSWinEventLog", "A member was removed from a security-enabled" ]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """({event_code}\d+)\s+Microsoft-Windows-Security-Auditing""",
    """\s({host}[^\s]+)\sMSWinEventLog""",
    """Information\s+({host}[\w.\-]+)\s+""",
    """(?:Success|Audit)\s+\w+\s+({host}[^\s]+)""",
    """A member was removed from a security-enabled\s+({group_type}.+?)\s+group.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)\s+Member:""",
    """Member:\s+Security ID:\s+({account_id}[^\s]+)\s+Account Name:\s*(-|({account_dn}CN=.+?OU.+?DC.+?))?\s*Group:\s+Security ID:\s+({group_id}[^\s]+)\s+(Group|Account) Name:\s*({group_name}.+?)?\s+(Group|Account) Domain:\s+({group_domain}.+?)\s+Additional""",
    """Member:.+?Account Name:\s*CN=.+?({account_ou}OU.+?DC.+?)\s+Group:""",
  ]
  DupFields = [ "host->dest_host" ]
}
```