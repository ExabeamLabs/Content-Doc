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
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>"""
    """<Data Name(\\)?='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name(\\)?='SubjectUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>(?=\w)({logon_id}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='TaskName'>(?=[\\\w])({task_name}[^<]{1,2000})</Data>""",
    """<UserId>(?=\w)(({account_domain}[^\\<]{0,2000})\\)?({account_name}[^<]{1,2000})</UserId>""",
    """<Settings>\s{0,100}({additional_info}.+?)\s{0,100}</Settings>""",
    """<Triggers>\s{0,100}({triggers}.+?)\s{0,100}</Triggers>""",
    """<RunLevel>(?=\w)({run_level}[^<]{1,2000})</RunLevel>""",
    """<LogonType>(?=\w)({logon_type}[^<]{1,2000})</LogonType>""",
    """<RegistrationInfo>.+?<Author>(?=\w)({author}[^<]{1,2000})</Author>""",
    """<RegistrationInfo>.+?<Description>(?=\w)({description}[^<]{1,2000})</Description>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]{1,2000})?[\\\/])?({process_name}[^<"]{1,2000}))""",
    """<Arguments>("{1,20})?({arg}[^<"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```