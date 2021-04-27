#### Parser Content
```Java
{
Name = s-xml-1102
  Vendor = Microsoft Windows
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
    """<Message>({additional_info}[^<]+)\s*<\/Message>""",
    """<Message>Process '?({process_name}[^\s']+)""",
    """<Security UserID(\\)?='({user_sid}[^']+)""",
    """<Execution ProcessID(\\)?='({process_id}[^']+)""",
    """<EventID[^<]*?>({event_code}\d+)""",
    """<Keyword>({outcome}[^<]+)</Keyword>""",
    """<Data Name(\\)?='ProcessName'>({process}({directory}[^<>]*?[\\\/]+)?({process_name}[^<>\\\/]+))</Data>""",
    """<Data Name='TargetProcessName'>({target_process}({target_directory}[^<>]*?[\\\/]+)?({target_process_name}[^<>\\\/]+))</Data>""",
    """<Data Name(\\)?='ProcessId'>({pid}[^<]+?)\s*</Data>""",
    """Security ID:\s*({user_sid}\S+)\s+Account Name:""",
    """Account Name:\s*(LOCAL SERVICE|-|({user}\S+))\s+Account Domain:""",
    """Account Domain:\s*(NT AUTHORITY|-|({domain}\S+))\s+Logon ID:""",
    """Logon ID:\s*({logon_id}\S+)\s+""",
    """Client IP: ({src_ip}[a-fA-F:\.\d]+)""",
    """ThreadID(\\)?='({thread_id}\d+)"""
  ]
}
```