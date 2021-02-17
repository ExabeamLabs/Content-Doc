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
  Fields = [ """UtcTime:\s*({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sComputer(?:Name)?\s*=\s*"?({host}[^\s"]+)""",
    """Message\s*=\s*"?({activity_type}[^:]+)""",
    """User\s*=\s*"(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)""",
    """SourceProcessGuid:\s*\{({process_guid}[^\s\}]+)""",
    """SourceProcessId:\s*({pid}\d+)""",
    """\s+SourceImage:\s*({process}({directory}(?:(\w+:)?[^:]+)?[\\\/])?({process_name}.+?))\s+TargetProcessGuid:""",
    """TargetProcessGuid:\s*\{({target_process_guid}[^\s\}]+)""",
    """TargetProcessId:\s*({target_pid}\d+)""",
    """\s+TargetImage:\s*({target_process}({target_directory}(?:(\w+:)?[^:]+)?[\\\/])?({target_process_name}.+?))\s+NewThreadId:"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```