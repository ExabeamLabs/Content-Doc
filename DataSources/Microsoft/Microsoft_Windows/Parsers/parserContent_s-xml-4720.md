#### Parser Content
```Java
{
Name = s-xml-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4720</EventID>", "<Data Name='TargetSid'>"]
  Fields = [ """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({account_id}[^<]+))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({account_name}[^<]+)</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({account_domain}[^<]+)</Data>""",
    """<Data Name='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='SubjectUserName'>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>(?=\w)({logon_id}[^<]+)</Data>""",
  ]
}
```