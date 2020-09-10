#### Parser Content
```Java
{
Name = xml-5861
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5861""" , """Microsoft-Windows-WMI-Activity"""]
  Fields = [
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<Security UserID='({user_sid}[^']+)""",
    """({process_name}WMI)""",
    """Query\s*=\s*"*({command_line}[^";]+)""",
    """Consumer:\s* instance of\s*({process}.+?)\s*\{"""
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = raw-4700
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-task-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """4700""", """A scheduled task was enabled""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+?)</Computer>""",
    """({event_id}4700)""",
    """({event_name}A scheduled task was enabled)""",
    """\sAccount Name:\s*(|({user}.+?))\s*Account Domain:\s*(|({domain}.+?))\s*Logon ID:\s*(|({logon_id}.+?))\s*Task Information:""",
    """Task Name:\s*({task_name}.+?)\s*Task Content:""",
    """Task Content:\s*({additional_info}.+?)\s*<""",
  ]
}
```