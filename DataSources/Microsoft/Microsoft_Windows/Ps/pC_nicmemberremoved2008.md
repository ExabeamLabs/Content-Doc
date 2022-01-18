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
    """({event_name}A member was removed from a security-enabled [\w\s]{1,2000} group)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """({event_code}4757|4729|4733)""",
    """({event_code}\d{1,100})\s{1,100}Microsoft-Windows-Security-Auditing""",
    """({host}[^\s=]{1,2000})\sMSWinEventLog""",
    """Information\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}""",
    """(?:Success|Audit)\s{1,100}\w+\s{1,100}({host}[^\s]{1,2000})""",
    """A member was removed from a security-enabled\s{1,100}({group_type}.+?)\s{1,100}group.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}Member:""",
    """Member:\s{1,100}Security ID:\s{1,100}({account_id}[^\s]{1,2000})\s{1,100}Account Name:\s{0,100}(-|({account_dn}CN=.+?OU.+?DC.+?))?\s{0,100}Group:\s{1,100}Security ID:\s{1,100}({group_id}[^\s]{1,2000})\s{1,100}(Group|Account) Name:\s{0,100}({group_name}.+?)?\s{1,100}(Group|Account) Domain:\s{1,100}({group_domain}.+?)\s{1,100}Additional""",
    """Member:.+?Account Name:\s{0,100}CN=.+?({account_ou}OU.+?DC.+?)\s{1,100}Group:""",
  ]
  DupFields = [ "host->dest_host" ]


}
```