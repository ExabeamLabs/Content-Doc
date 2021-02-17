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
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Keywords>({outcome}[^<]+)</Keywords>""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]+)</Data>""",
    """<Data Name='SubjectUserName'>({user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
    """<Data Name='TargetSid'>({target_user_sid}[^<]+)</Data>""",
    """<Data Name='TargetUserName'>({target_user}[^<]+)</Data>""",
    """<Data Name='TargetDomainName'>({target_domain}[^<]+)</Data>"""
  ]
  DupFields = [ "host->dest_host" ]
}
```