#### Parser Content
```Java
{
Name = s-xml-4724
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-password-reset"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4724</EventID>", "<Data Name='TargetSid'>"]
  Fields = [ """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({target_user_sid}[^<]+))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({target_user}[^<]+)</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({target_domain}[^<]+)</Data>""",
    """<Data Name='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='SubjectUserName'>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>(?=\w)({logon_id}[^<]+)</Data>""",
    """<Keyword>({outcome}[^<]+?)<\/Keyword>""",
    """({event_name}An attempt was made to reset an account's password)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```