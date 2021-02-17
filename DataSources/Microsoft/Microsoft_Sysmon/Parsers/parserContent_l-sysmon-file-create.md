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
    """<EventID>({event_code}\d+)</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d+)""",
    """created:UtcTime:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='(({domain}[^\\>]+?)\\)?({user}.+?)'\s*/>""",
    """<EventData>.*?Image:\s*({process}({directory}.*?)({process_name}[^.\\]+\.exe))\s*TargetFilename:""",
    """<EventData>.*?Image:\s*({path}.+?)\s*TargetFilename:""",
    """TargetFilename:\s*({file_path}({file_parent}.*?)({file_name}[^\\.]+(\.({file_ext}[^\\.]+?))?))\s*CreationUtcTime:""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```