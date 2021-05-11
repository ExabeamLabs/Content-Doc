#### Parser Content
```Java
{
Name = l-sysmon-file-create
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """logrhythm:""", """<EventID>11</EventID>""" ]
  Fields = [
    """<Provider Name='Microsoft-Windows-Sysmon' Guid='\{({process_guid}[^}]+?)\}""",
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d{1,100})""",
    """created:UtcTime:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='(({domain}[^\\>]+?)\\)?({user}.+?)'\s{0,100}/>""",
    """<EventData>.*?Image:\s{0,100}({process}({directory}.*?)({process_name}[^.\\]+\.exe))\s{0,100}TargetFilename:""",
    """<EventData>.*?Image:\s{0,100}({path}.+?)\s{0,100}TargetFilename:""",
    """TargetFilename:\s{0,100}({file_path}({file_parent}.*?)({file_name}[^\\.]+(\.({file_ext}[^\\.]+?))?))\s{0,100}CreationUtcTime:""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```