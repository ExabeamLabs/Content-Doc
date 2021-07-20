#### Parser Content
```Java
{
Name = s-xml-1102
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSS"""
  Conditions = [  """>1102</EventID>""",       """<TimeCreated SystemTime="""    ]
  Fields = [
    """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}[^<>]{1,2000})<\/Computer>""",
    """<Message>({event_name}[^:<\.]{1,2000})""",
    """<Message>({event_name}[^<]{1,2000}?)\.(\s|<)""",
    """<Message>({additional_info}[^<]{1,2000})\s{0,100}<\/Message>""",
    """<Message>Process '?({process_name}[^\s']{1,2000})""",
    """<Security UserID(\\)?='({user_sid}[^']{1,2000})""",
    """<Execution ProcessID(\\)?='({process_id}[^']{1,2000})""",
    """<EventID[^<]{0,2000}?>({event_code}\d{1,100})""",
    """<Keyword>({outcome}[^<]{1,2000})</Keyword>""",
    """<Data Name(\\)?='ProcessName'>({process}({directory}[^<>]{0,2000}?[\\\/]{1,2000})?({process_name}[^<>\\\/]{1,2000}))</Data>""",
    """<Data Name='TargetProcessName'>({target_process}({target_directory}[^<>]{0,2000}?[\\\/]{1,2000})?({target_process_name}[^<>\\\/]{1,2000}))</Data>""",
    """<Data Name(\\)?='ProcessId'>({pid}[^<]{1,2000}?)\s{0,100}</Data>""",
    """Security ID:\s{0,100}({user_sid}\S+)\s{1,100}Account Name:""",
    """Account Name:\s{0,100}(LOCAL SERVICE|-|({user}\S+))\s{1,100}Account Domain:""",
    """Account Domain:\s{0,100}(NT AUTHORITY|-|({domain}\S+))\s{1,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}\S+)\s{1,100}""",
    """Client IP: ({src_ip}[a-fA-F:\.\d]{1,2000})""",
    """ThreadID(\\)?='({thread_id}\d{1,100})"""
  ]
}
```