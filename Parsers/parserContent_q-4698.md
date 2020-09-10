#### Parser Content
```Java
{
Name = q-4698
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-task-created"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventID=4698", "A scheduled task was created" ]
  Fields = [ 
    """\WComputer=({host}[\w\.\-]+)""",
    """\WEventID=({event_code}\d+)""",
    """\WTimeGenerated=({time}\d+)""",
    """\sAccount Name:\s*(|({user}.+?))\s*Account Domain:\s*(|({domain}.+?))\s*Logon ID:\s*(|({logon_id}.+?))\s*Task Information:""",
    """\sTask Name:\s*(|(?=[\\\w])({task_name}.+?))\s*Task Content:""",
    """<UserId>(?=\w)(({account_domain}[^\\<]*)\\)?({account_name}[^<]+)</UserId>""",
    """<RunLevel>(?=\w)({run_level}[^<]+)</RunLevel>""",
    """<RegistrationInfo>.+?<Description>(?=\w)({description}[^<]+)</Description>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]+)?[\\\/])?({process_name}[^<"]+))""",
    """<Arguments>("+)?({arg}[^<"]+)"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```