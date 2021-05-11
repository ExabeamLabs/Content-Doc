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
    """(Success Audit|Audit Success|Information)<\d{1,100}>({host}[^<]+)<""",
    """>({event_code}\d{1,100})<\d{1,100}>Microsoft-Windows-Security-Auditing""",
    """A member was added to a security-enabled ({group_type}[^\s]+) group""",
    """Subject:.+?Account Name:\s{0,100}(#011)*({user}[^\s#]+)\s{0,100}(#011)*\s{0,100}Account Domain""",
    """<Data Name='SubjectUserName'>(\#011)*({user}[^\s#]+?)\s{0,100}(\#\d{1,100})*\s{0,100}<""",
    """Subject:.+?Account Domain:\s{0,100}(\#011)*({domain}[^\s#]+?)\s{0,100}(\#011)*\s{0,100}Logon ID""",
    """Logon ID:\s{0,100}(\#011)*({logon_id}[^\s#]+?)\s{0,100}(\#011)*\s{0,100}Member:""",
    """Member:.*?Security ID:\s{0,100}({account_id}(?=[^\\:]+\\)({sid_domain}[^\\:]+)\\({sid_user}[^\s]+)|(?:[^\s]+))\s{0,100}Account Name:""",
    """Member:(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))|(?:.+?))\s{0,100}Group:""",
    """Group:\s{0,100}Security ID:\s{0,100}({group_id}.+?)\s{0,100}(Group|Account) Name""",
    """Group:.+?(Group|Account) Name:\s{0,100}(\#011)*({group_name}.+?)\s{0,100}(\#011)*\s{0,100}(Group|Account) Domain:""",
    """Group:.+?(Group|Account) Domain:\s{0,100}(\#011)*({group_domain}[^\s#]+)\s{0,100}(\#011)*\s{0,100}(Additional Information:)?""",
  ]
  DupFields = [ "host->dest_host" ]
}
```