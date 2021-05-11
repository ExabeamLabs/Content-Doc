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
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{4})\s{1,100}47\d\d\s{1,100}Microsoft""",
    """"_raw":"({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_source=({host}[A-Fa-f:\d.]+)""",
    """\s(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[\w.\-]+)""",
    """ComputerName\\=({host}[\w\-.]+)""",
    """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s|;)""",
    """({event_code}4728|4732|4756)""",
    """({event_code}47\d\d)(\s{1,100}|,)Microsoft-Windows-Security-Auditing""",
    """"EventID":"({event_code}\d{1,100})""",
    """EventCode\\=({event_code}\d{1,100})""",
    """Account Name:\s{0,100}({user}[^\s]+)\s{0,100}Account Domain:\s{0,100}({domain}[^\s]+)\s{0,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}[^\s]+)""",
    """Member:\s{0,100}Security ID:\s{0,100}({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\+({sid_user}.+?)|(?:.+?))\s{0,100}Account Name:""",
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """Account Name:\s{0,100}(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))?\s{0,100}Group:""",
    """Group:\s{0,100}Security ID:\s{0,100}(None|({group_id}[^\s]+))\s{0,100}(Group|Account) Name:\s{0,100}(None|({group_name}.+?))?\s{0,100}(Group|Account) Domain:\s{0,100}(None|({group_domain}[^\s]+))""",
    """Subject:\s{1,100}[^:]+:\s{1,100}\S+\s{1,100}Account Name:\s{1,100}({user}[^:]+?)\s{1,100}Account Domain:\s{1,100}({domain}[^:]+?)\s{1,100}Logon ID:""",
    """Member:\s{1,100}[^:]+:\s{1,100}\S+\s{1,100}Account Name:\s{1,100}CN=({account}[^,]+)""",
    """Security(,|\s{1,100})({record_id}\d{1,100})""",
    """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
    """"MemberName":"(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))?""",
    """"TargetAccount":"(({group_domain}[^\\\s"]+)\\+)?({group_name}[^\\\s"]+)""",
    """"MemberSid":"({account_id}[^\s"]+)""",
    """"ManagementGroupName":"({group_name}[^\s"]+)""",
    """"SubjectLogonId":"({logon_id}[^\s"]+)""",
    """"TargetSid":"({group_id}[^\s"]+)""",
    """"data\.system_name":"({host}[^"]+)"""",
    """"data\.id":"({event_code}\d{1,100})""""
  ]
  DupFields = [ "host->dest_host" ]
}
```