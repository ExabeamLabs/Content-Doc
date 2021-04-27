#### Parser Content
```Java
{
Name = xml-4688
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4688</EventID>", """'SubjectUserSid'>""" ]
  Fields = [
    """<TimeCreated SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_name}A new process has been created)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]+?)</Data>""",
    """<Data Name(\\)?='SubjectUserName'>({user}[^<]+?)</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]+?)</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+?)</Data>""",
    """<Data Name(\\)?='NewProcessId'>({process_guid}[x\da-f]+)</Data>""",
    """<Data Name(\\)?='NewProcessName'>({process}({directory}(?:[^<>]+)?[\\\/])?({process_name}[^\\\/<>]+))</Data>""",
    """<Data Name(\\)?='NewProcessName'>({path}[^<]+?)</Data>""",
    """<Data Name(\\)?='CommandLine'>\s*({command_line}[^<]+?)\s*</Data>""",
    """<Data Name(\\)?='CommandLine'>\s*(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s*(?:\\*[\w.\-]+)?\s*create\s*({service_name}.+?))\s+binPath= ({process}({directory}(?:[^<>]+)?[\\\/])?({process_name}[^\\\/<>]+))</Data>""",
    """<Data Name(\\)?='ProcessId'>({parent_process_guid}[x\da-f]+)</Data>""",
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```