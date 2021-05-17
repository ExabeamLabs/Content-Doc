#### Parser Content
```Java
{
Name = s-xml-4723
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4723</EventID>", "<Data Name='PrivilegeList'>" ]
  Fields = ["""SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Keywords>({outcome}[^<]{1,2000})</Keywords>""",
    """<Keyword>({outcome}Audit\s[^<]{1,2000})</Keyword>""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectUserName'>({user}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
    """<Data Name='TargetSid'>({target_user_sid}[^<]{1,2000})</Data>""",
    """<Data Name='TargetUserName'>({target_user}[^<]{1,2000})</Data>""",
    """<Data Name='TargetDomainName'>({target_domain}[^<]{1,2000})</Data>"""
  ]
  DupFields = [ "host->dest_host" ]
}
```