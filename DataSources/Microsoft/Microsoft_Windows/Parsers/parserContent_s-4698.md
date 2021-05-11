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
    """\sComputerName=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sKeywords=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Security ID:\s{0,100}(|({user_sid}.+?))\s{0,100}Account Name:\s{0,100}(|({user}.+?))\s{0,100}Account Domain:\s{0,100}(|({domain}.+?))\s{0,100}Logon ID:\s{0,100}(|({logon_id}.+?))\s{0,100}Task Information:""",
    """Task Name:\s{0,100}(|({task_name}.+?))\s{0,100}Task Content:""",
    """<UserId>(?=\w)(({account_domain}[^\\<]*)\\)?({account_name}[^<]+)</UserId>""",
    """<Settings>\s{0,100}({additional_info}.+?)\s{0,100}</Settings>""",
    """<Triggers>\s{0,100}({triggers}.+?)\s{0,100}</Triggers>""",
    """<RunLevel>(?=\w)({run_level}[^<]+)</RunLevel>""",
    """<LogonType>(?=\w)({logon_type}[^<]+)</LogonType>""",
    """<RegistrationInfo>.+?<Author>(?=\w)({author}[^<]+)</Author>""",
    """<RegistrationInfo>.+?<Description>(?=\w)({description}[^<]+)</Description>""",
    """<Command>"?({process}({directory}(?:(\w+:)?[^:<"]+)?[\\\/])?({process_name}[^<"]+))""",
    """<Arguments>("{1,20})?({arg}[^<"]+)"""
    """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```