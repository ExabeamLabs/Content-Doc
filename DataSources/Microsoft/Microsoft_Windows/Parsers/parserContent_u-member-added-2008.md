#### Parser Content
```Java
{
Name = u-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Sumo
  DataType = "windows-member-added"
  TimeFormat = "yyyyMMddHHmmss.SSS"
  Conditions = [ "EventCode = 47", """"A member was added to a security-enabled """, """TimeGenerated = """ ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """Computer(Name)? = "{1,20}({host}[^"]+)"""",
    """EventCode = ({event_code}\d{1,100})""",
    """TimeGenerated = "({time}[\d]+.\d\d\d)""",
    """A member was added to a security-enabled ({group_type}[^\s]+) group""",
    """Subject:.+?Account Name:\s{1,100}({user}[^\s]+)\s{1,100}Account Domain:\s{1,100}({domain}[^\s]+)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}""",
    """Member:\s{1,100}Security ID:\s{1,100}({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s{1,100}Account Name:""",
    """Member:(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))|(?:.+?))\s{1,100}Group:""",
    """Group:\s{1,100}Security ID:\s{1,100}({group_id}[^\s]+)\s{1,100}Group Name:""",
    """Group:.+?(Group|Account) Name:\s{1,100}({group_name}.+?)?\s{1,100}(Group|Account) Domain:""",
    """Group:.+?(Group|Account) Domain:\s{1,100}({group_domain}[^\s]+)\s{1,100}Additional""",
  ]
  DupFields = [ "host->dest_host" ]
}
```