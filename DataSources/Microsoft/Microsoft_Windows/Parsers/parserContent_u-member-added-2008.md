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
    """Computer(Name)? = "+({host}[^"]+)"""",
    """EventCode = ({event_code}\d+)""",
    """TimeGenerated = "({time}[\d]+.\d\d\d)""",
    """A member was added to a security-enabled ({group_type}[^\s]+) group""",
    """Subject:.+?Account Name:\s+({user}[^\s]+)\s+Account Domain:\s+({domain}[^\s]+)\s+Logon ID:\s+({logon_id}[^\s]+)\s+""",
    """Member:\s+Security ID:\s+({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s+Account Name:""",
    """Member:(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))|(?:.+?))\s+Group:""",
    """Group:\s+Security ID:\s+({group_id}[^\s]+)\s+Group Name:""",
    """Group:.+?(Group|Account) Name:\s+({group_name}.+?)?\s+(Group|Account) Domain:""",
    """Group:.+?(Group|Account) Domain:\s+({group_domain}[^\s]+)\s+Additional""",
  ]
  DupFields = [ "host->dest_host" ]
}
```