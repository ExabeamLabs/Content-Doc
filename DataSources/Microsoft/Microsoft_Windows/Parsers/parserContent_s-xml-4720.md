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
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({account_id}[^<]{1,2000}))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({account_name}[^<]{1,2000})</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({account_domain}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name='SubjectUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectLogonId'>(?=\w)({logon_id}[^<]{1,2000})</Data>""",
  ]
  DupFields = ["host->dest_host"]
}
```