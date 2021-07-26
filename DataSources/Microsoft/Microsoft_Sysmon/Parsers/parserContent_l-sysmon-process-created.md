#### Parser Content
```Java
{
Name = l-sysmon-process-created
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>1</EventID>""" ]
  Fields = [
    """<Provider Name='Microsoft-Windows-Sysmon' Guid='\{({process_guid}[^}]{1,2000}?)\}""",
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d{1,100})""",
    """UtcTime:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='(({domain}[^\\>]{1,2000}?)\\)?({user}.+?)'\s{0,100}/>""",
    """<EventData>.*?Image:\s{0,100}({process}({directory}.*?)({process_name}[^.\\]{1,2000}\.exe))\s{0,100}CommandLine:""",
    """<EventData>.*?Image:\s{0,100}({path}.+?)\s{0,100}CommandLine:""",
    """CommandLine:\s{0,100}({command_line}.*?)\s{0,100}CurrentDirectory:""",
    """,MD5=({md5}[^,]{1,2000})(,|\s{0,100}$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```