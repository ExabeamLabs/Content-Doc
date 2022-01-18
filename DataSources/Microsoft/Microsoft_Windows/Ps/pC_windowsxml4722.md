#### Parser Content
```Java
{
Name = windows-xml-4722
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-enabled"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4722</EventID>""", """<Data Name ='TargetSid'>""","""<Data Name ='TargetUserName'>""", """<Message>A user account was enabled""" ]
  Fields = [ 
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """({event_code}4722)""",
    """({event_name}A user account was enabled)"""
    """<Data Name ='TargetSid'>(?:NONE_MAPPED|({target_user_sid}[^<]{1,2000}))<""",
    """<Data Name ='TargetUserName'>({target_user}[^<]{1,2000})<""",
    """<Data Name ='TargetDomainName'>({target_domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))<""",
    """<Data Name ='SubjectUserName'>({user}[^<]{1,2000})<""",
    """<Data Name ='SubjectDomainName'>({domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})<"""
  ]


}
```