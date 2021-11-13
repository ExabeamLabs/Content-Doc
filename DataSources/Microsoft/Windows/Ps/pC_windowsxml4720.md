#### Parser Content
```Java
{
Name = windows-xml-4720
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "windows-account-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4720</EventID>""", """<Data Name ='TargetSid'>""","""<Message>A user account was created"""]
  Fields = [ 
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})<""",
    """({event_code}4720)""",
    """<Data Name ='TargetSid'>(?:NONE_MAPPED|({account_id}[^<]{1,2000}))<""",
    """<Data Name ='TargetUserName'>({account_name}[^<]{1,2000})<""",
    """<Data Name ='TargetDomainName'>({account_domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))<""",
    """<Data Name ='SubjectUserName'>({user}[^<]{1,2000})<""",
    """<Data Name ='SubjectDomainName'>({domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})<""",
    """({event_name}A user account was created)"""
  ]
  DupFields = ["host->dest_host"]


}
```