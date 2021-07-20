#### Parser Content
```Java
{
Name = json-4698
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct 
  DataType = "windows-task-created"
  TimeFormat = "epoch"
  Conditions = [ """"EventID":4698""", """A scheduled task was created""" ]
  Fields = [
    """"EventTime":"?({time}[^",]{1,2000})""",
    """"Hostname":"({host}[\w.-]{1,2000}?)"""",
    """"EventID":({event_code}\d{1,100})""",
    """({event_name}A scheduled task was created)""",
    """"SubjectUserName":"({user}[^"]{1,2000})""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
    """"TaskName":"({task_name}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"Keywords":"({outcome}[^,"]{1,2000})""",
    """"ProcessID":({pid}\d{1,100})""",
    """"ThreadID":({thread_id}\d{1,100})""",
    """<UserId>(?=\w)(({account_domain}[^\\<]{0,2000})\\)?({account_name}[^<]{1,2000})</UserId>""",
    """<Settings>[\\rnt\s]{0,2000}({additional_info}[^"]{1,2000}?)\s{0,100}[\\rnt\s]{0,2000}<\/Settings>""",
    """<Triggers>[\\rtn\s]{0,2000}({triggers}[^"]{1,2000}?)[\\rtn\s]{0,2000}<\/Triggers>""",
    """<RunLevel>(?=\w)({run_level}[^<]{1,2000})</RunLevel>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]{1,2000})?[\\\/])?({process_name}[^<"]{1,2000}))""",
    """<Arguments>("{1,20})?({arg}[^<"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```