#### Parser Content
```Java
{
Name = windows-xml-4700
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-task-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4700</EventID>""", """<Data Name ='SubjectUserName'>""", """<Message>A scheduled task was enabled""" ]
  Fields = [ 
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """({event_code}4700)""",
    """({event_name}A scheduled task was enabled)""",
    """<Data Name ='SubjectUserName'>({user}[^<]{1,2000})<""",
    """<Data Name ='SubjectDomainName'>({domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})<"""
    """<Data Name ='TaskName'>({task_name}[^<]{1,2000})<""",
    """<Data Name ='TaskContent'>({additional_info}[^<]{1,2000})<"""
  ]


}
```