#### Parser Content
```Java
{
Name = s-xml-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-lockout"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4740</EventID>", "<Data Name ='TargetSid'>"]
  Fields = [ """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name ='SubjectUserName'>({caller_user}[^<]{1,2000})</Data>""",
    """<Data Name ='SubjectDomainName'>({caller_domain}[^<]{1,2000})</Data>""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
    """<Data Name ='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name ='TargetUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name ='SubjectDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>"""
  ]
  DupFields = [ "host->dest_host" ]


}
```