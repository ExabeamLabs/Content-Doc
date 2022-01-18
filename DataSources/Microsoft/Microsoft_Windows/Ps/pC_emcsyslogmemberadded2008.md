#### Parser Content
```Java
{
Name = emc-syslog-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """__li_source_path="""", "A member was added to a security-enabled", """eventid="""" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """eventid="({event_code}47\d\d)"""",
    """__li_source_path="({host}[^"]{1,2000})"""",
    """Subject:.+?Account Name:\s{1,100}({user}[^\s]{1,2000}).+?Account Domain:\s{1,100}({user_domain}[^\s]{1,2000}).*Member""",
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}""",
    """Member:\s{1,100}Security ID:\s{1,100}({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}.+?)|(?:.+?))\s{1,100}Account Name:""",
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """(Information|Audit Success|Success Audit),({host}[\w.\-]{1,2000}),""",
    """Member:.+?Account Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC.+?))\s{1,100} Group:""",
    """Group:\s{1,100}Security ID:\s{1,100}({group_id}[^\s]{1,2000})""",
    """Group:.+?(Group|Account) Name:\s{1,100}({group_name}.+?)?\s{1,100}(Group|Account) Domain:""",
    """Group:.+?(Group|Account) Domain:\s{1,100}({group_domain}[^\s]{1,2000})""",
  ]
  DupFields = [ "host->dest_ip" ]


}
```