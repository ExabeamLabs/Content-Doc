#### Parser Content
```Java
{
Name = s-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-added"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """LogName =""", """SourceName =""", "EventCode=", "A member was added to a security-enabled" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """exabeam_raw=.*?({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """ComputerName =({host}[\w.\-]{1,2000})""",
    """EventCode=({event_code}[\w]{1,2000})""",
    """A member was added to a security-enabled ({group_type}[^\s]{1,2000}) group""",
    """Subject:.+?Account Name:\s{1,100}({user}[^\s]{1,2000})""",
    """Account Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}""",
    """Member:\s{1,100}Security ID:\s{1,100}({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}.+?)|(?:.+?))\s{1,100}Account Name:""",
    """Member:(.+?({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))|(?:.+?))\s{1,100}Group:""",
    """Group:\s{1,100}Security ID:\s{1,100}({group_id}[^\s]{1,2000})""",
    """Group:.+?(Group|Account) Name:\s{1,100}({group_name}.+?)?\s{1,100}(Group|Account) Domain:""",
    """Group:.+?(Group|Account) Domain:\s{1,100}({group_domain}[^\s]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" ]


}
```