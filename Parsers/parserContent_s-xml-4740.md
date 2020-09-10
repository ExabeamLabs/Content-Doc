#### Parser Content
```Java
{
Name = s-xml-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-lockout"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4740</EventID>", "<Data Name='TargetSid'>"]
  Fields = [ """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name='SubjectUserName'>({caller_user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>({caller_domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>(?=\w)({domain}[^<]+)</Data>"""
  ]
  DupFields = [ "host->dest_host" ]
}
```