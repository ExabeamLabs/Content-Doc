#### Parser Content
```Java
{
Name = sysmon-process-created-1
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """CreateRemoteThread detected:""" ]
  Fields = [ """UtcTime:\s{0,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sComputer(?:Name)?\s{0,100}=\s{0,100}"?({host}[^\s"]+)""",
    """Message\s{0,100}=\s{0,100}"?({activity_type}[^:]+)""",
    """User\s{0,100}=\s{0,100}"(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)""",
    """SourceProcessGuid:\s{0,100}\{({process_guid}[^\s\}]+)""",
    """SourceProcessId:\s{0,100}({pid}\d{1,100})""",
    """\s{1,100}SourceImage:\s{0,100}({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s{1,100}TargetProcessGuid:""",
    """TargetProcessGuid:\s{0,100}\{({target_process_guid}[^\s\}]+)""",
    """TargetProcessId:\s{0,100}({target_pid}\d{1,100})""",
    """\s{1,100}TargetImage:\s{0,100}({target_process}({target_directory}(?:(\w+:)?[^:]+)?[\\\/])?({target_process_name}.+?))\s{1,100}NewThreadId:"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```