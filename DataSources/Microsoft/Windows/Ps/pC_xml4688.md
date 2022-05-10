#### Parser Content
```Java
{
Name = xml-4688
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4688</EventID>", """'SubjectUserSid'>""" ]
  Fields = [
    """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_name}A new process has been created)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """({event_code}4688)""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]{1,2000}?)</Data>""",
    """<Data Name(\\)?='SubjectUserName'>(-|LOCAL SERVICE|({user}[^<]{1,2000}?))</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>(-|NT AUTHORITY|({domain}[^<]{1,2000}?))</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000}?)</Data>""",
    """<Data Name(\\)?='NewProcessId'>({process_guid}[x\da-f]{1,2000})</Data>""",
    """<Data Name(\\)?='NewProcessName'>({process}({directory}(?:[^<>]{1,2000})?[\\\/])?({process_name}[^\\\/<>]{1,2000}))</Data>""",
    """<Data Name(\\)?='CommandLine'>"?\s{0,100}({command_line}[^<]{1,2000}?)\s{0,100}"?</Data>""",
    """<Data Name(\\)?='CommandLine'>\s{0,100}(|-|(sc|((?:[^"]{1,2000})?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]{1,2000})?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= ({process}({directory}(?:[^<>]{1,2000})?[\\\/])?({process_name}[^\\\/<>]{1,2000}))</Data>""",
    """<Data Name(\\)?='ProcessId'>({parent_process_guid}[x\da-f]{1,2000})</Data>""",
    """<Data Name ='ParentProcessName'>({parent_process}({parent_directory}[^<]{1,2000}[\\\/]{1,2000})?({parent_process_name}[^<]{1,2000}))<\/Data>"""
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory","process->path" ]


}
```