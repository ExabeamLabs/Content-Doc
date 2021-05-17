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
    """\WComputer=({host}[\w\.\-]{1,2000})""",
    """\WEventID=({event_code}\d{1,100})""",
    """\WTimeGenerated=({time}\d{1,100})""",
    """\sAccount Name:\s{0,100}(|({user}.+?))\s{0,100}Account Domain:\s{0,100}(|({domain}.+?))\s{0,100}Logon ID:\s{0,100}(|({logon_id}.+?))\s{0,100}Task Information:""",
    """\sTask Name:\s{0,100}(|(?=[\\\w])({task_name}.+?))\s{0,100}Task Content:""",
    """<UserId>(?=\w)(({account_domain}[^\\<]{0,2000})\\)?({account_name}[^<]{1,2000})</UserId>""",
    """<RunLevel>(?=\w)({run_level}[^<]{1,2000})</RunLevel>""",
    """<RegistrationInfo>.+?<Description>(?=\w)({description}[^<]{1,2000})</Description>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]{1,2000})?[\\\/])?({process_name}[^<"]{1,2000}))""",
    """<Arguments>("{1,20})?({arg}[^<"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```