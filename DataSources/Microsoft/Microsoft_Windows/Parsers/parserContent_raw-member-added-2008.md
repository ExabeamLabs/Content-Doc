#### Parser Content
```Java
{
Name = raw-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """A member was added to a security-enabled""" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """({time}\w+ \d+ \d+:\d+:\d+ \d{4})\s+47\d\d\s+Microsoft""",
    """"_raw":"({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_source=({host}[A-Fa-f:\d.]+)""",
    """(?i)(((audit|success)( |_)(success|audit))|information)(\s+|,)({host}[\w.\-]+)""",
    """ComputerName\\=({host}[\w\-.]+)""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s|;)""",
    """({event_code}4728|4732|4756)""",
    """({event_code}47\d\d)(\s+|,)Microsoft-Windows-Security-Auditing""",
    """"EventID":"({event_code}\d+)""",
    """EventCode\\=({event_code}\d+)""",
    """Account Name:\s*({user}[^\s]+)\s*Account Domain:\s*({domain}[^\s]+)\s*Logon ID:""",
    """Logon ID:\s*({logon_id}[^\s]+)""",
    """Member:\s*Security ID:\s*({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\+({sid_user}.+?)|(?:.+?))\s*Account Name:""",
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """Account Name:\s*(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))?\s*Group:""",
    """Group:\s*Security ID:\s*(None|({group_id}[^\s]+))\s*(Group|Account) Name:\s*(None|({group_name}.+?))?\s*(Group|Account) Domain:\s*(None|({group_domain}[^\s]+))""",
    """Security(,|\s+)({record_id}\d+)""",
    """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
    """"MemberName":"(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))?""",
    """"TargetAccount":"(({group_domain}[^\\\s"]+)\\+)?({group_name}[^\\\s"]+)""",
    """"MemberSid":"({account_id}[^\s"]+)""",
    """"ManagementGroupName":"({group_name}[^\s"]+)""",
    """"SubjectLogonId":"({logon_id}[^\s"]+)""",
    """"TargetSid":"({group_id}[^\s"]+)""",
    """"data\.system_name":"({host}[^"]+)"""",
    """"data\.id":"({event_code}\d+)""""
  ]
  DupFields = [ "host->dest_host" ]
}
```