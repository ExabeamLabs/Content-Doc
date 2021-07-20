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
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name='SubjectUserName'>({user}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({target_user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({target_user}[^<]{1,2000})</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({target_domain}[^<]{1,2000})</Data>""",
  ]
  DupFields = [ "host->dest_host" ]
}
```