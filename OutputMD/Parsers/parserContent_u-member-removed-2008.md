#### Parser Content
```Java
{
Name = u-member-removed-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Sumo
  DataType = "windows-member-removed"
  TimeFormat = "yyyyMMddHHmmss.SSS"
  Conditions = [ "EventCode = 47", """A member was removed from a security-enabled """ ]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """Computer(Name)? = "+({host}[^"]+)"""",
   """EventCode = ({event_code}\d+)""",
   """TimeGenerated = "({time}[\d]+.\d\d\d)""",
   """A member was removed from a security-enabled ({group_type}[^\s]+) group""",
   """Subject:.+?Account Name:\s+({user}[^\s]+)""",
   """Account Domain:\s+({domain}[^\s]+)""",
   """Logon ID:\s+({logon_id}[^\s]+)\s+""",
   """Member:\s+Security ID:\s+({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s+Account Name:""",
   """Member:(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))|(?:.+?))\s+Group:""",
   """Group:\s+Security ID:\s+({group_id}[^\s]+)""",
   """Group:.+?(Group|Account) Name:\s+({group_name}.+?)?\s+(Group|Account) Domain:""",
   """Group:.+?(Group|Account) Domain:\s+({group_domain}[^\s]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```