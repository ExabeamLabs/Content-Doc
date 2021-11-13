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
    """\$Message\s{0,100}=\s{0,100}"({event_name}[^"]{1,2000})""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """<TimeCreated SystemTime='({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{3})""",
    """EventCode=({event_code}\d{1,100})""",
    """ComputerName =({host}[\w.\-]{1,2000})""",
    """<EventID[^>]{0,2000}>({event_code}\d{1,100})</EventID>""",
    """<Computer>({host}[^<>]{1,2000})</Computer>""",
    """Sid=({user_sid}[\w\-]{1,2000})""",
    """<Execution ProcessID='({pid}\d{1,100})""",
    """<Security UserID='({user_sid}[\w\-]{1,2000})'/>""",
    """Context[^@]{1,2000}?User\s{0,100}=\s{0,100}(({domain}[^=]{1,2000}?)[\\\/]{1,2000})?(SYSTEM|({user}[^=\/\\]{1,2000}?))\s{0,100}Connected User =""",
    """Context[^@]{1,2000}?Host Application\s{0,100}=\s{0,100}({command_line}.+?)\s{0,100}Engine Version =""",
    """Context[^@]{1,2000}?Host Application\s{0,100}=\s{0,100}({process}(({directory}[^\;=]{1,2000})[\\\/]{1,2000})?({process_name}[^\s\\\/=]{1,2000}?))\s{1,100}""",
    """Context[^@]{1,2000}?Command Type\s{0,100}=\s{0,100}(|({command_type}[^=]{1,2000}?))\s{0,100}Script Name =""",
    """Context[^@]{1,2000}?Command Name\s{0,100}=\s{0,100}(|({command_name}[^=]{1,2000}?))\s{0,100}Command Type =""",
    """Context[^@]{1,2000}?Script Name\s{0,100}=\s{1,100}({script_name}\S[^=]{1,2000}?)\s{1,100}Command Path =""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]


}
```