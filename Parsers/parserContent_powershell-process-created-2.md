#### Parser Content
```Java
{
Name = powershell-process-created-2
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """Microsoft-Windows-PowerShell""", """Context:""" ]
  Fields = [
    """\$Message\s*=\s*"({event_name}[^"]+)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """<TimeCreated SystemTime='({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d{3})""",
    """EventCode=({event_code}\d+)""",
    """ComputerName=({host}[\w.\-]+)""",
    """<EventID[^>]*>({event_code}\d+)</EventID>""",
    """<Computer>({host}[^<>]+)</Computer>""",
    """Sid=({user_sid}[\w\-]+)""",
    """<Execution ProcessID='({pid}\d+)""",
    """<Security UserID='({user_sid}[\w\-]+)'/>""",
    """Context.+?User\s*=\s*(({domain}[^=]+?)[\\\/]+)?({user}[^=\/\\]+?)\s*Connected User =""",
    """Context.+?Host Application\s*=\s*({command_line}[^=]+?)\s*Engine Version =""",
    """Context.+?Host Application\s*=\s*({process}(({directory}[^\;=]+)[\\\/]+)?({process_name}[^\s\\\/=]+?))\s+""",
    """Context.+?Command Type\s*=\s*(|({command_type}[^=]+?))\s*Script Name =""",
    """Context.+?Command Name\s*=\s*(|({command_name}[^=]+?))\s*Command Type =""",
    """Context.+?Script Name\s*=\s+({script_name}\S[^=]+?)\s+Command Path =""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```