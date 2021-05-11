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
    """<Computer>({host}[^<>]+)<\/Computer>""",
    """<Message>({event_name}[^:<\.]+)""",
    """<Message>({event_name}[^<]+?)\.(\s|<)""",
    """<Message>({additional_info}[^<]+)\s{0,100}<\/Message>""",
    """<Message>Process '?({process_name}[^\s']+)""",
    """<Security UserID(\\)?='({user_sid}[^']+)""",
    """<Execution ProcessID(\\)?='({process_id}[^']+)""",
    """<EventID[^<]*?>({event_code}\d{1,100})""",
    """<Keyword>({outcome}[^<]+)</Keyword>""",
    """<Data Name(\\)?='ProcessName'>({process}({directory}[^<>]*?[\\\/]+)?({process_name}[^<>\\\/]+))</Data>""",
    """<Data Name='TargetProcessName'>({target_process}({target_directory}[^<>]*?[\\\/]+)?({target_process_name}[^<>\\\/]+))</Data>""",
    """<Data Name(\\)?='ProcessId'>({pid}[^<]+?)\s{0,100}</Data>""",
    """Security ID:\s{0,100}({user_sid}\S+)\s{1,100}Account Name:""",
    """Account Name:\s{0,100}(LOCAL SERVICE|-|({user}\S+))\s{1,100}Account Domain:""",
    """Account Domain:\s{0,100}(NT AUTHORITY|-|({domain}\S+))\s{1,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}\S+)\s{1,100}""",
    """Client IP: ({src_ip}[a-fA-F:\.\d]+)""",
    """ThreadID(\\)?='({thread_id}\d{1,100})"""
  ]
}
```