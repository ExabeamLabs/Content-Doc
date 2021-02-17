#### Parser Content
```Java
{
Name = powershell-process-created-3
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<Provider Name='PowerShell'/>""", """ScriptName=""", """CommandLine=""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d{3})""",
    """<EventID[^>]*>({event_code}\d+)</EventID>""",
    """<Computer>({host}[^<>]+)</Computer>""",
    """<Execution ProcessID='({pid}\d+)""",
    """<Security UserID='({user_sid}[\w\-]+)'/>""",
    """\WUserId=(({domain}[^=]+?)[\\\/]+)?(SYSTEM|({user}[^=\/\\]+?))\s*HostName=""",
    """\WHostApplication=({command_line}[^=]+?)\s*EngineVersion=""",
    """\WHostApplication=({process}(({directory}[^\;=]+)[\\\/]+)?({process_name}[^\s\\\/=]+?))\s+""",
    """\WScriptName=({script_name}\S[^=]+?)\s+Command(Path|Line)="""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```