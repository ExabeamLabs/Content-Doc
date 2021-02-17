#### Parser Content
```Java
{
Name = l-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ">47", ">A member was added to a security-enabled" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """(Success Audit|Audit Success|Information)<\d+>({host}[^<]+)<""",
    """>({event_code}\d+)<\d+>Microsoft-Windows-Security-Auditing""",
    """A member was added to a security-enabled ({group_type}[^\s]+) group""",
    """Subject:.+?Account Name:\s*(#011)*({user}[^\s#]+)\s*(#011)*\s*Account Domain""",
    """<Data Name='SubjectUserName'>(\#011)*({user}[^\s#]+?)\s*(\#\d+)*\s*<""",
    """Subject:.+?Account Domain:\s*(\#011)*({domain}[^\s#]+?)\s*(\#011)*\s*Logon ID""",
    """Logon ID:\s*(\#011)*({logon_id}[^\s#]+?)\s*(\#011)*\s*Member:""",
    """Member:.*?Security ID:\s*({account_id}(?=[^\\:]+\\)({sid_domain}[^\\:]+)\\({sid_user}[^\s]+)|(?:[^\s]+))\s*Account Name:""",
    """Member:(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))|(?:.+?))\s*Group:""",
    """Group:\s*Security ID:\s*({group_id}.+?)\s*(Group|Account) Name""",
    """Group:.+?(Group|Account) Name:\s*(\#011)*({group_name}.+?)\s*(\#011)*\s*(Group|Account) Domain:""",
    """Group:.+?(Group|Account) Domain:\s*(\#011)*({group_domain}[^\s#]+)\s*(\#011)*\s*(Additional Information:)?""",
  ]
  DupFields = [ "host->dest_host" ]
}
```