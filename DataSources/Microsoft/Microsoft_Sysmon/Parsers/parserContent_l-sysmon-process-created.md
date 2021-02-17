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
    """<Provider Name='Microsoft-Windows-Sysmon' Guid='\{({process_guid}[^}]+?)\}""",
    """<EventID>({event_code}\d+)</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d+)""",
    """UtcTime:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='(({domain}[^\\>]+?)\\)?({user}.+?)'\s*/>""",
    """<EventData>.*?Image:\s*({process}({directory}.*?)({process_name}[^.\\]+\.exe))\s*CommandLine:""",
    """<EventData>.*?Image:\s*({path}.+?)\s*CommandLine:""",
    """CommandLine:\s*({command_line}.*?)\s*CurrentDirectory:""",
    """,MD5=({md5}[^,]+)(,|\s*$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```