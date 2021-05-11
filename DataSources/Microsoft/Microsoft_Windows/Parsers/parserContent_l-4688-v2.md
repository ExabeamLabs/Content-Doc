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
    """Creator Subject:\s{0,100}Security ID:\s{0,100}(|-|({user_sid}.+?))\s{0,100}Account Name:\s{0,100}(|-|LOCAL SERVICE|({user}.+?))\s{0,100}Account Domain:\s{0,100}(|-|NT AUTHORITY|({domain}.+?))\s{0,100}Logon ID:\s{0,100}(|-|({logon_id}.+?))\s{0,100}Target Subject:""",
   """<Data Name='SubjectUserSid'>({user_sid}[^<]+)<\/Data>""",
   """<Data Name='SubjectUserName'>(LOCAL SERVICE|({user}[^<]+))<\/Data>""",
   """<Data Name='SubjectDomainName'>(NT AUTHORITY|({domain}[^<]+))<\/Data>""",
   """<Data Name='SubjectLogonId'>({logon_id}[^<]+)<\/Data>""",
   """New Process ID:\s{0,100}({process_guid}[x\da-f]+)""",
   """<Data Name='NewProcessId'>\s{0,100}({process_guid}[x\da-f]+)<\/Data>""",
   """New Process Name:\s{0,100}(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s{0,100}Token Elevation Type:""",
   """<Data Name='NewProcessName'>\s{0,100}(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s{0,100}<\/Data><Data Name='TokenElevationType'>""",
   """New Process Name:\s{0,100}(|-|({path}.+?))\s{0,100}Token Elevation Type:""",
   """<Data Name='NewProcessName'>\s{0,100}(|-|({path}.+?))\s{0,100}<\/Data>""",
   """Process Command Line:\s{0,100}(|-|({command_line}.+?))\s{0,100}Token Elevation Type""",
   """Process Command Line:\s{0,100}(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]+)?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= \s{0,100}(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s{0,100}Token Elevation Type""",
   """<Data Name='CommandLine'>\s{0,100}(|-|({command_line}.+?))\s{0,100}<\/Data><Data Name='TargetUserSid'>""",
   """Creator Process ID:\s{0,100}({parent_process_guid}[x\da-f]+)""",
   """<Data Name='ProcessId'>\s{0,100}({parent_process_guid}[x\da-f]+)<\/Data>""",
   """({activity_type}Process Creation)""",
   """<Data Name='ParentProcessName'>({parent_process}({parent_directory}[^<]+[\\\/]+)?({parent_process_name}[^<]+))<\/Data>"""
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```