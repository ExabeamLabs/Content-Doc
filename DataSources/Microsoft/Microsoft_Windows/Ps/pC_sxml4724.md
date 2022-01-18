#### Parser Content
```Java
{
Name = s-xml-4724
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-password-reset"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4724</EventID>""", """<Data Name ='TargetSid'>""" ]
  Fields = [ 
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}({dest_host}[\w-]{1,2000})[^<]{0,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name ='TargetSid'>(?:NONE_MAPPED|({target_user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name ='TargetUserName'>(?=\w)({target_user}[^<]{1,2000})</Data>""",
    """<Data Name ='TargetDomainName'>(?=\w)({target_domain}[^<]{1,2000})</Data>""",
    """<Data Name ='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name ='SubjectUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name ='SubjectDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name ='SubjectLogonId'>(?=\w)({logon_id}[^<]{1,2000})</Data>""",
    """<Keyword>({outcome}[^<]{1,2000}?)<\/Keyword>""",
    """({event_name}An attempt was made to reset an account's password)"""
  ]


}
```