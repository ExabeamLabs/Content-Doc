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
    """\WEventID=({event_code}\d{1,100})""",
    """\WTimeGenerated=({time}\d{1,100})""",
    """\sAccount Name:\s{0,100}(|({user}.+?))\s{0,100}Account Domain:\s{0,100}(|({domain}.+?))\s{0,100}Logon ID:\s{0,100}(|({logon_id}.+?))\s{0,100}Task Information:""",
    """\sTask Name:\s{0,100}(|(?=[\\\w])({task_name}.+?))\s{0,100}Task Content:""",
    """<UserId>(?=\w)(({account_domain}[^\\<]*)\\)?({account_name}[^<]+)</UserId>""",
    """<RunLevel>(?=\w)({run_level}[^<]+)</RunLevel>""",
    """<RegistrationInfo>.+?<Description>(?=\w)({description}[^<]+)</Description>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]+)?[\\\/])?({process_name}[^<"]+))""",
    """<Arguments>("{1,20})?({arg}[^<"]+)"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```