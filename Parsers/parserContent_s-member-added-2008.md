#### Parser Content
```Java
{
Name = s-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-added"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """LogName=""", """SourceName=""", "EventCode=", "A member was added to a security-enabled" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """exabeam_raw=.*?({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """ComputerName=({host}[\w.\-]+)""",
    """EventCode=({event_code}[\w]+)""",
    """A member was added to a security-enabled ({group_type}[^\s]+) group""",
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