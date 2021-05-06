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
    """"EventTime":"?({time}[^",]+)""",
    """"Hostname":"({host}[\w.-]+?)"""",
    """"EventID":({event_code}\d+)""",
    """({event_name}A scheduled task was created)""",
    """"SubjectUserName":"({user}[^"]+)""",
    """"SubjectDomainName":"({domain}[^"]+)"""",
    """"SubjectUserSid":"({user_sid}[^"]+)""",
    """"TaskName":"({task_name}[^"]+)"""",
    """"SubjectLogonId":"({logon_id}[^"]+)"""",
    """"Keywords":"({outcome}[^,"]+)""",
    """"ProcessID":({pid}\d+)""",
    """"ThreadID":({thread_id}\d+)""",
    """<UserId>(?=\w)(({account_domain}[^\\<]*)\\)?({account_name}[^<]+)</UserId>""",
    """<Settings>[\\rnt\s]*({additional_info}[^"]+?)\s*[\\rnt\s]*<\/Settings>""",
    """<Triggers>[\\rtn\s]*({triggers}[^"]+?)[\\rtn\s]*<\/Triggers>""",
    """<RunLevel>(?=\w)({run_level}[^<]+)</RunLevel>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]+)?[\\\/])?({process_name}[^<"]+))""",
    """<Arguments>("+)?({arg}[^<"]+)"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```