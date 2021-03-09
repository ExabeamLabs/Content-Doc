#### Parser Content
```Java
{
Name = s-xml-4698
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-task-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4698</EventID>", "'TaskName'>"]
  Fields = [ 
    """SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>"""
    """<Data Name(\\)?='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name(\\)?='SubjectUserName'>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>(?=\w)({logon_id}[^<]+)</Data>""",
    """<Data Name(\\)?='TaskName'>(?=[\\\w])({task_name}[^<]+)</Data>""",
    """<UserId>(?=\w)(({account_domain}[^\\<]*)\\)?({account_name}[^<]+)</UserId>""",
    """<Settings>\s*({additional_info}.+?)\s*</Settings>""",
    """<Triggers>\s*({triggers}.+?)\s*</Triggers>""",
    """<RunLevel>(?=\w)({run_level}[^<]+)</RunLevel>""",
    """<LogonType>(?=\w)({logon_type}[^<]+)</LogonType>""",
    """<RegistrationInfo>.+?<Author>(?=\w)({author}[^<]+)</Author>""",
    """<RegistrationInfo>.+?<Description>(?=\w)({description}[^<]+)</Description>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]+)?[\\\/])?({process_name}[^<"]+))""",
    """<Arguments>("+)?({arg}[^<"]+)"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```