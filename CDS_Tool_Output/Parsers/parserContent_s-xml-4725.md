#### Parser Content
```Java
{
Name = s-xml-4725
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-disabled"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4725</EventID>", "<Data Name='TargetSid'>"]
  Fields = [ """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='SubjectUserName'>({user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({target_user_sid}[^<]+))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({target_user}[^<]+)</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({target_domain}[^<]+)</Data>""",
  ]
  DupFields = [ "host->dest_host" ]
}
```