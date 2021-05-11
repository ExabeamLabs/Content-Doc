#### Parser Content
```Java
{
Name = powershell-process-created-2
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """Microsoft-Windows-PowerShell""", """Context:""" ]
  Fields = [
    """\$Message\s{0,100}=\s{0,100}"({event_name}[^"]+)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """<TimeCreated SystemTime='({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{3})""",
    """EventCode=({event_code}\d{1,100})""",
    """ComputerName=({host}[\w.\-]+)""",
    """<EventID[^>]*>({event_code}\d{1,100})</EventID>""",
    """<Computer>({host}[^<>]+)</Computer>""",
    """Sid=({user_sid}[\w\-]+)""",
    """<Execution ProcessID='({pid}\d{1,100})""",
    """<Security UserID='({user_sid}[\w\-]+)'/>""",
    """Context[^@]+?User\s{0,100}=\s{0,100}(({domain}[^=]+?)[\\\/]+)?(SYSTEM|({user}[^=\/\\]+?))\s{0,100}Connected User =""",
    """Context[^@]+?Host Application\s{0,100}=\s{0,100}({command_line}.+?)\s{0,100}Engine Version =""",
    """Context[^@]+?Host Application\s{0,100}=\s{0,100}({process}(({directory}[^\;=]+)[\\\/]+)?({process_name}[^\s\\\/=]+?))\s{1,100}""",
    """Context[^@]+?Command Type\s{0,100}=\s{0,100}(|({command_type}[^=]+?))\s{0,100}Script Name =""",
    """Context[^@]+?Command Name\s{0,100}=\s{0,100}(|({command_name}[^=]+?))\s{0,100}Command Type =""",
    """Context[^@]+?Script Name\s{0,100}=\s{1,100}({script_name}\S[^=]+?)\s{1,100}Command Path =""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```