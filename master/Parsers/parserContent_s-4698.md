#### Parser Content
```Java
{
Name = s-4698
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-task-created"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """4698""", """A scheduled task was created""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """({event_code}4698)""",
    """({event_name}A scheduled task was created)""",
    """\sComputerName=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\sKeywords=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """Security ID:\s*(|({user_sid}.+?))\s*Account Name:\s*(|({user}.+?))\s*Account Domain:\s*(|({domain}.+?))\s*Logon ID:\s*(|({logon_id}.+?))\s*Task Information:""",
    """Task Name:\s*(|({task_name}.+?))\s*Task Content:""",
    """<UserId>(?=\w)(({account_domain}[^\\<]*)\\)?({account_name}[^<]+)</UserId>""",
    """<Settings>\s*({additional_info}.+?)\s*</Settings>""",
    """<Triggers>\s*({triggers}.+?)\s*</Triggers>""",
    """<RunLevel>(?=\w)({run_level}[^<]+)</RunLevel>""",
    """<LogonType>(?=\w)({logon_type}[^<]+)</LogonType>""",
    """<RegistrationInfo>.+?<Author>(?=\w)({author}[^<]+)</Author>""",
    """<RegistrationInfo>.+?<Description>(?=\w)({description}[^<]+)</Description>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]+)?[\\\/])?({process_name}[^<"]+))""",
    """<Arguments>("+)?({arg}[^<"]+)"""
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```