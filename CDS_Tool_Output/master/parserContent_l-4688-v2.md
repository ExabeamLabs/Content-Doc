#### Parser Content
```Java
{
Name = l-4688-v2
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4688</EventID>", "A new process has been created", "Creator Subject:" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """Creator Subject:\s*Security ID:\s*(|-|({user_sid}.+?))\s*Account Name:\s*(|-|({user}.+?))\s*Account Domain:\s*(|-|({domain}.+?))\s*Logon ID:\s*(|-|({logon_id}.+?))\s*Target Subject:""",
   """<Data Name='SubjectUserSid'>({user_sid}[^<]+)<\/Data>""",
   """<Data Name='SubjectUserName'>({user}[^<]+)<\/Data>""",
   """<Data Name='SubjectDomainName'>({domain}[^<]+)<\/Data>""",
   """<Data Name='SubjectLogonId'>({logon_id}[^<]+)<\/Data>""",
   """New Process ID:\s*({process_guid}[x\da-f]+)""",
   """<Data Name='NewProcessId'>\s*({process_guid}[x\da-f]+)<\/Data>""",
   """New Process Name:\s*(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s*Token Elevation Type:""",
   """<Data Name='NewProcessName'>\s*(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s*<\/Data><Data Name='TokenElevationType'>""",
   """New Process Name:\s*(|-|({path}.+?))\s*Token Elevation Type:""",
   """<Data Name='NewProcessName'>\s*(|-|({path}.+?))\s*<\/Data>""",
   """Process Command Line:\s*(|-|({command_line}.+?))\s*Token Elevation Type""",
   """<Data Name='CommandLine'>\s*(|-|({command_line}.+?))\s*<\/Data><Data Name='TargetUserSid'>""",
   """Creator Process ID:\s*({parent_process_guid}[x\da-f]+)""",
   """<Data Name='ProcessId'>\s*({parent_process_guid}[x\da-f]+)<\/Data>""",
   """({activity_type}Process Creation)""",
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```