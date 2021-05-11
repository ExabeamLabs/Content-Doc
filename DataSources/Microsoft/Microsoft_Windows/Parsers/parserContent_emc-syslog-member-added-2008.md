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
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """eventid="({event_code}47\d\d)"""",
    """__li_source_path="({host}[^"]+)"""",
    """Subject:.+?Account Name:\s{1,100}({user}[^\s]+).+?Account Domain:\s{1,100}({user_domain}[^\s]+).*Member""",
    """Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}""",
    """Member:\s{1,100}Security ID:\s{1,100}({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}.+?)|(?:.+?))\s{1,100}Account Name:""",
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """(Information|Audit Success|Success Audit),({host}[\w.\-]+),""",
    """Member:.+?Account Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC.+?))\s{1,100} Group:""",
    """Group:\s{1,100}Security ID:\s{1,100}({group_id}[^\s]+)""",
    """Group:.+?(Group|Account) Name:\s{1,100}({group_name}.+?)?\s{1,100}(Group|Account) Domain:""",
    """Group:.+?(Group|Account) Domain:\s{1,100}({group_domain}[^\s]+)""",
  ]
  DupFields = [ "host->dest_ip" ]
}
```