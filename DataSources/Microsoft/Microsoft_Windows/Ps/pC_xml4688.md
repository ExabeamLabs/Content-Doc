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
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]{1,2000}?)</Data>""",
    """<Data Name(\\)?='SubjectUserName'>(?:LOCAL SERVICE|({user}[^<]{1,2000}?))</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>(?:NT AUTHORITY|({domain}[^<]{1,2000}?))</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000}?)</Data>""",
    """<Data Name(\\)?='NewProcessId'>({process_guid}[x\da-f]{1,2000})</Data>""",
    """<Data Name(\\)?='NewProcessName'>({process}({directory}(?:[^<>]{1,2000})?[\\\/])?({process_name}[^\\\/<>]{1,2000}))</Data>""",
    """<Data Name(\\)?='NewProcessName'>({path}[^<]{1,2000}?)</Data>""",
    """<Data Name(\\)?='CommandLine'>"?\s{0,100}({command_line}[^<]{1,2000}?)\s{0,100}"?</Data>""",
    """<Data Name(\\)?='CommandLine'>\s{0,100}(|-|(sc|((?:[^"]{1,2000})?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]{1,2000})?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= ({process}({directory}(?:[^<>]{1,2000})?[\\\/])?({process_name}[^\\\/<>]{1,2000}))</Data>""",
    """<Data Name(\\)?='ProcessId'>({parent_process_guid}[x\da-f]{1,2000})</Data>""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}({parameter_sct}\S+\.sct)""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}"({parameter_sct}[^<]{1,2000}?\.sct)"""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}({parameter_hta}\S+\.hta)""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}"({parameter_hta}[^<]{1,2000}?\.hta)"""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}({parameter_xml}\S+\.xml)""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}\s{1,100}"({parameter_xml}[^<]{1,2000}?\.xml)"""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}({parameter_csproj}\S+\.csproj)""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}"({parameter_csproj}[^<]{1,2000}?\.csproj)"""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}["\s]({parameter_exe}[^<]{1,2000}?\.exe)""",
    """<Data Name(\\)?='CommandLine'>"?[^<]{0,2000}?\s{1,100}["\s]({parameter_dll}[^<]{1,2000}?\.dll)""",
    """<Data Name ='ParentProcessName'>({parent_process}({parent_directory}[^<]{1,2000}[\\\/]{1,2000})?({parent_process_name}[^<]{1,2000}))<\/Data>"""
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]


}
```